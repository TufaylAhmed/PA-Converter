<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 13/5/16 - 12:11
 */
//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

include_once INC_ROOT.'/libs/PaloAltoNetworks/Middleware/loadCSRFControl.php';

require_once INC_ROOT.'/libs/database.php';

$request_body   = file_get_contents('php://input');
$data           = json_decode($request_body, true);

parse_str(file_get_contents("php://input"),$post_vars);
if(isset($post_vars['type'])){
    $type = $pandb->real_escape_string($post_vars['type']);
}
else {
    $type = $pandb->real_escape_string((string)(isset($_GET['type']) ? $_GET['type'] : ''));
}
$project    = $pandb->real_escape_string((string)(isset($_GET['project'])      ? $_GET['project']  : ''));

if (isset($_SESSION['timezone'])){
    date_default_timezone_set($_SESSION['timezone']);
}

switch($_SERVER['REQUEST_METHOD'])
{
    case 'GET':
        $message = list_db();
        if($message['code']) {
            $totalDevices = count($message['msg']);
            echo json_encode(array('total' => $totalDevices, 'projects' => $message['msg']));
        }
        else{
            echo '{"total":"0","projects":[]}';
        }
        break;

    case 'POST':
        $action = "post";
        if(!isset($data)) {
            echo json_encode(array('success' => true, 'msg' => 'Nothing to do'));
            die();
        }
        $message = register_Project($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'PUT':
        $action = "put";
        if(!isset($data)) {
            echo json_encode(array('success' => true, 'msg' => 'Nothing to do'));
            die();
        }
        $message = update_Project($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    case 'DELETE':
        $message = delete_Project($data);
        echo json_encode(array('success' => $message['code'], 'msg' => $message['msg']));
        break;

    default:
        break;
}

function list_db() {
    require_once INC_ROOT.'/userManager/API/projects/list.php';
    $message = listProjects();

    $databases = array();
    if($message['code']) {
        foreach ($message['msg'] as $project) {
            if ($project->vendors == "") {
                $project->vendors = "none";
            }
            $value = $project->progress;
            $project->progress = "<img src=/resources/images/progress/bar_" . $project->progress . ".gif>";
            $project->progress_value = $value;

            $accessValid = listViewProject($project->name);
            if ($accessValid) {
                $project->admin = listAdminProject($project->name);
                $databases[] = $project;
            }
        }
    }
    $message['msg'] = $databases;

    return $message;
}


function register_Project($data){
    require_once INC_ROOT.'/userManager/API/projects/register.php';
    $message = registerProject($data);
    if ($message['code']){
        clone_db($data);
        return $message;
    }
    else{
//        $message= [
//            'code'   => false,
//            'msg'       =>"You do not have permissions to create this project. <br/>Check the project's name and/or Contact your administrator."
//        ];
        return $message;
    }
}

function update_Project(ARRAY $data){
    require_once INC_ROOT.'/userManager/API/projects/update.php';
    if(isset($data['action'])){
        switch($data['action']){
            case 'addVendor':
                $message = addVendor($data);
                break;
            default:
                break;
        }
    }
    else{
        $message = updateProject($data);
    }
    return $message;
}

function clone_db($data) {
    global $app;
    $project    = $data['name'];
    $tag        = $data['tag'];
    $source     = $data['source'];

    $db1 = new mysqli(DBServer, DBUser, DBPass);

    if ($tag == "Ex. Customer Name") {
        $tag = "";
    }
    if ($db1->connect_error) {
        trigger_error('Database connection failed: ' . $db1->connect_error, E_USER_ERROR);
    }
    $sql = "CREATE DATABASE " . $project;
    $db1->query($sql);
    if ($db1->error) {
        echo json_encode(array("success" => false, "msg" => "Error while creating the Database"));
    }
    else {
        mysqli_close($db1);

        $PROJECTPATH = USERSPACE_PATH."/projects/";
        if (!file_exists($PROJECTPATH)) {
            $oldmask = umask(0);
            mkdir($PROJECTPATH, 0766, true);
            umask($oldmask);
        }
        $PROJECTPATHCOMPLETE = $PROJECTPATH . $project;
        if (!is_dir($PROJECTPATHCOMPLETE)) {
            mkdir($PROJECTPATHCOMPLETE, 0766, true);
        }

        $PROJECBACKUPTPATHCOMPLETE = $PROJECTPATHCOMPLETE."/Backups";
        if (!is_dir($PROJECBACKUPTPATHCOMPLETE)) {
            mkdir($PROJECBACKUPTPATHCOMPLETE, 0766, true);
        }
//        mkdir($PROJECTPATH . $project . "/Backups", 0766);

        $mysql_file = create_mysql_file();
        //$Command = "mysql -u".DBUser." -p".DBPass." $project < ".INC_ROOT."/OS/SQL/project_schema.sql";
        $Command = "mysql --defaults-extra-file=$mysql_file $project < ".INC_ROOT."/OS/SQL/project_schema.sql";
        exec($Command);
        delete_mysql_dump_file($mysql_file);

//        $db2 = new mysqli(DBServer, DBUser, DBPass, 'pandb');
//        if ($db2->connect_error) {
//            trigger_error('Database connection failed: ' . $db2->connect_error, E_USER_ERROR);
//            $message = [
//                'success'   => false,
//                'msg'       => 'Database connection failed: ' . $db2->connect_error,
//            ];
//            return $message;
//        }
//
//        $sql = "INSERT INTO projects (name,date,progress,tag) VALUES ('$project',NOW(),0,'$tag')";  //TODO: Delete this entry
//        $db2->query($sql);
//        mysqli_close($db2);

        #LOAD APPS , THREATS and REGIONS
        $DBName = $project;
        $db1 = new mysqli(DBServer, DBUser, DBPass, $DBName);

        if ($db1->connect_error) {
            trigger_error('Database connection failed', E_USER_ERROR);
            $message = [
                'success'   => false,
                'msg'       => 'Database connection failed',
            ];
            return $message;
        }

        # Load all the common patches to the new Database
        foreach (glob(INC_ROOT."/OS/SQL/updates/*.common") as $filename) {
            $file=basename($filename);
            $updateDB="CREATE TABLE  `updates` (`id` int(11) NOT NULL AUTO_INCREMENT,`datetime` datetime DEFAULT NULL,`filename` varchar(255) DEFAULT NULL,PRIMARY KEY (`id`)) ENGINE=MyISAM DEFAULT CHARSET=utf8;";
            $result=$db1->query($updateDB);
            $db1->query("INSERT INTO updates (datetime,filename) VALUES (NOW(),'$file');");
        }

        if ($source == "") {
            $source = "default";
        }

        if ($source == "default") {
            #Default from CONTENTS
            $xml  = simplexml_load_file(INC_ROOT.'/contents/applications.xml');
            $xml2 = simplexml_load_file(INC_ROOT.'/contents/applications-container.xml');
            $xml3 = simplexml_load_file(INC_ROOT.'/contents/region.xml');
//            $xml4 = simplexml_load_file(INC_ROOT.'/contents/threats.xml');
            //$xml5 = simplexml_load_file(INC_ROOT.'/contents/url_categories.xml');

            $versions = simplexml_load_file(INC_ROOT.'/contents/versions.xml');
            $panos = $versions->panos;
            $appversion = $versions->applications;
            $urldb = $versions->url_categories;
            $threats = $versions->threats;

            $projectObject = $app->project->where('name', $project)->get()->first();
            $params = [
                'panos'         => $panos,
                'appversion'    => $appversion,
                'threatversion' => $threats,
                'urldb'         => $urldb,
            ];
            $projectObject->update($params);

        }
        else {
            #LOAD FROM DEVICES
            if ((file_exists(USERSPACE_PATH.'/devices/'.$source.'/applications.xml')) AND
                (filesize(USERSPACE_PATH.'/devices/' . $source . '/applications.xml') != 0)) {
                $xml = simplexml_load_file(USERSPACE_PATH.'/devices/'.$source.'/applications.xml');
            }
            else {
                $xml = simplexml_load_file(INC_ROOT.'/contents/applications.xml');
            }

            if ((file_exists(USERSPACE_PATH.'/devices/'.$source.'/applications-container.xml')) AND
                (filesize(USERSPACE_PATH.'/devices/'.$source.'/applications-container.xml') != 0)) {
                $xml2 = simplexml_load_file(USERSPACE_PATH.'/devices/'.$source.'/applications-container.xml');
            }
            else {
                $xml2 = simplexml_load_file(INC_ROOT.'/contents/applications-container.xml');
            }

            if ((file_exists(USERSPACE_PATH.'/devices/'.$source.'/region.xml')) AND
                (filesize(USERSPACE_PATH.'/devices/'.$source.'/region.xml') != 0)) {
                $xml3 = simplexml_load_file(USERSPACE_PATH.'/devices/'.$source.'/region.xml');
            }
            else {
                $xml3 = simplexml_load_file(INC_ROOT.'/contents/region.xml');
            }

            //TODO. Include the known threats to the project
//            if ((file_exists(INC_ROOT.'/devices/'.$source.'/threats.xml')) AND
//                (filesize(INC_ROOT.'/devices/'.$source.'/threats.xml') != 0)) {
//                $xml4 = simplexml_load_file(INC_ROOT.'/devices/'.$source.'/threats.xml');
//            }
//            else {
//                $xml4 = simplexml_load_file(INC_ROOT.'/contents/threats.xml');
//            }


//            if ((file_exists(USERSPACE_PATH.'/devices/'.$source.'/url_categories.xml')) AND
//                (filesize(USERSPACE_PATH.'/devices/'.$source.'/url_categories.xml') != 0)) {
//                $xml5 = simplexml_load_file(USERSPACE_PATH.'/devices/'.$source.'/url_categories.xml');
//            } else {
//                $xml5 = simplexml_load_file(INC_ROOT.'/contents/url_categories.xml');
//            }

        }

        $apps = array();
        $appsObjects = array();

        foreach ($xml->result->application->entry as $value) {

            $default_port = "";
            $default_protocol = "";

            $certifications = "no";

            $is_fedramp = "no";
            $is_hipaa = "no";
            $is_pci = "no";
            $is_soc1 = "no";
            $is_soc2 = "no";
            $is_ssae16 = "no";
            $is_truste = "no";

            $is_data_breaches = "no";
            $is_ip_based_restrictions = "no";
            $is_poor_financial_viability = "no";
            $is_poor_terms_of_service = "no";

            $default_value_array = array();
            $dependency_array = array();
//            $dependency_final = array();
            $app_container = "";
//            $dependency = "";

//            $var = $value->attributes()->name;

            if (isset($value->{'use-applications'})) {
                foreach ($value->{'use-applications'}->member as $kkkey => $vvvalue) {
                    $dependency_array[] = substr($vvvalue, 0);
                }
            }

            $dependency_implicit = array();
            if (isset($value->{'implicit-use-applications'})) {
                foreach ($value->{'implicit-use-applications'}->member as $vvvalue) {
                    $dependency_implicit[] = substr($vvvalue, 0);
                }
                $dependency_final = array_diff($dependency_array, $dependency_implicit);
                $dependency_array = $dependency_final;
            }

            if (isset($value->{'application-container'})) {
                $app_container = substr($value->{'application-container'}, 0);
            }

            if (count($dependency_implicit) > 0) {
                $implicit = implode(",", $dependency_implicit);
            }
            else {
                $implicit = "";
            }

            $dependency = implode(",", $dependency_array);

            if (isset($value->default->port)) {
                foreach ($value->default->port->member as $vvvalue) {
                    $default_value_array[] = trim($vvvalue->__toString());
                }
                $default_port = implode(",", $default_value_array);
                $default_port = str_replace(' ', '',$default_port);
            }
            elseif (isset($value->default->{'ident-by-ip-protocol'})) {
                $default_protocol = (string) $value->default->{'ident-by-ip-protocol'};
            }
            $ori_country=$value->attributes()->ori_country->__toString();
            if (isset($value->{'is-saas'})){$issaas=$value->{'is-saas'};}else{$issaas="no";}

            $evasive_behavior = $value->{'evasive-behavior'};
            $consume_big_bandwidth = $value->{'consume-big-bandwidth'};
            $used_by_malware = $value->{'used-by-malware'};
            $able_to_transfer_file = $value->{'able-to-transfer-file'};
            $has_known_vulnerability = $value->{'has-known-vulnerability'};
            $tunnel_other_application = $value->{'tunnel-other-application'};
            $prone_to_misuse = $value->{'prone-to-misuse'};
            $pervasive_use = $value->{'pervasive-use'};

            // New version 8.1

            if (isset($value->saas)){

                if(isset($value->saas->certifications)){

                    $certifications = "yes";

                    if (isset($value->saas->certifications->{'is-fedramp'})){
                        $is_fedramp = $value->saas->certifications->{'is-fedramp'};
                    }
                    if (isset($value->saas->certifications->{'is-hipaa'})){
                        $is_hipaa = $value->saas->certifications->{'is-hipaa'};
                    }
                    if (isset($value->saas->certifications->{'is-pci'})){
                        $is_pci = $value->saas->certifications->{'is-pci'};
                    }
                    if (isset($value->saas->certifications->{'is-soc1'})){
                        $is_soc1 = $value->saas->certifications->{'is-soc1'};
                    }
                    if (isset($value->saas->certifications->{'is-soc2'})){
                        $is_soc2 = $value->saas->certifications->{'is-soc2'};
                    }
                    if (isset($value->saas->certifications->{'is-ssae16'})){
                        $is_ssae16 = $value->saas->certifications->{'is-ssae16'};
                    }
                    if (isset($value->saas->certifications->{'is-truste'})){
                        $is_truste = $value->saas->certifications->{'is-truste'};
                    }
                }
                else{
                    $certifications = "no";
                }

                if (isset($value->saas->{'is-data-breaches'})){
                    $is_data_breaches = $value->saas->{'is-data-breaches'};
                }
                if (isset($value->saas->{'is-ip-based-restrictions'})){
                    $is_ip_based_restrictions = $value->saas->{'is-ip-based-restrictions'};
                }
                if (isset($value->saas->{'is-poor-financial-viability'})){
                    $is_poor_financial_viability = $value->saas->{'is-poor-financial-viability'};
                }
                if (isset($value->saas->{'is-poor-terms-of-service'})){
                    $is_poor_terms_of_service = $value->saas->{'is-poor-terms-of-service'};
                }
            }

            //echo "------>is_fedramp: " .$is_fedramp. "\n";
            //echo "------>is_truste: " .$is_truste. "\n";
            //echo "------>is_data_breaches: " .$is_data_breaches. "\n";

            $var = $value->attributes()->name->__toString();

            if ($var != "") {
                $appObject = new AppDependency(
                    $app_container,
                    $implicit,
                    $var, //Name
                    $value->technology->__toString(),
                    $value->risk->__toString(),
                    $value->category->__toString(),
                    $value->subcategory->__toString(),
                    $default_port,
                    $default_protocol,
                    $dependency_array,
                    $evasive_behavior->__toString(),
                    $consume_big_bandwidth->__toString(),
                    $used_by_malware->__toString(),
                    $able_to_transfer_file->__toString(),
                    $has_known_vulnerability->__toString(),
                    $tunnel_other_application->__toString(),
                    $prone_to_misuse->__toString(),
                    $pervasive_use->__toString(),
                    $ori_country,
                    $issaas,
                    $certifications,
                    $is_fedramp,
                    $is_hipaa,
                    $is_pci,
                    $is_soc1,
                    $is_soc2,
                    $is_ssae16,
                    $is_truste,
                    $is_data_breaches,
                    $is_ip_based_restrictions,
                    $is_poor_financial_viability,
                    $is_poor_terms_of_service
                );
//                var_dump($var);
                $appsObjects["$var"] = $appObject;
//                $apps[] = "('$app_container','$implicit','$var','$value->technology','$value->risk','$value->category','$value->subcategory','$default_port','$default_protocol','$dependency', '$evasive_behavior', '$consume_big_bandwidth', '$used_by_malware', '$able_to_transfer_file', '$has_known_vulnerability', '$tunnel_other_application', '$prone_to_misuse', '$pervasive_use')";
            }
        }

        //Explode the dependencies
        $appsObjects = explode_app_dependency($appsObjects);

        //Prepare the inserts
        foreach ($appsObjects as $appOb){
            $apps[] = "(
               '$appOb->container',
               '$appOb->implicit',
               '$appOb->name',
               '$appOb->technology',
               '$appOb->risk',
               '$appOb->category',
               '$appOb->subcategory',
               '$appOb->default_port',
               '$appOb->default_protocol',
               '".implode(",",$appOb->getDependencies()) ."', 
               '$appOb->evasive_behavior', 
               '$appOb->consume_big_bandwidth', 
               '$appOb->used_by_malware', 
               '$appOb->able_to_transfer_file', 
               '$appOb->has_known_vulnerability', 
               '$appOb->tunnel_other_application', 
               '$appOb->prone_to_misuse', 
               '$appOb->pervasive_use',
               '$appOb->ori_country',
               '$appOb->issaas',
               '$appOb->certifications',
               '$appOb->is_fedramp', 
               '$appOb->is_hipaa', 
               '$appOb->is_pci', 
               '$appOb->is_soc1', 
               '$appOb->is_soc2', 
               '$appOb->is_truste', 
               '$appOb->is_data_breaches', 
               '$appOb->is_ip_based_restrictions',
               '$appOb->is_poor_financial_viability',
               '$appOb->is_poor_terms_of_service'
                )";
        }

        if (count($apps) > 0) {
            $out = implode(",", $apps);
            $query = "INSERT INTO default_applications 
                (container, implicit, name, technology, risk, category, subcategory, default_port, default_protocol, 
                dependency, evasive_behavior, consume_big_bandwidth, used_by_malware, able_to_transfer_file, has_known_vulnerability, 
                tunnel_other_application, prone_to_misuse, pervasive_use,ori_country, is_saas, certifications,
                is_fedramp, is_hipaa, is_pci, is_soc1, is_soc2, is_truste, is_data_breaches, is_ip_based_restrictions, is_poor_financial_viability,
                is_poor_terms_of_service) 
                
                VALUES " . $out . ";";
            //echo $query;
            $db1->query($query);
        }

        $apps = array();
        foreach ($xml2->result->{'application-container'}->entry as $value) {
            $functions_array = array();
            $functions = "";
            if (isset($value->{'functions'})) {
                foreach ($value->{'functions'}->member as $vvvalue) {
                    $functions_array[] = substr($vvvalue, 0);
                }
                $functions = implode(",", $functions_array);
            }

            #Calculate Dependencies for Functions
            if (count($functions_array) > 0) {
                $newList = array();
                foreach ($functions_array as $depval) {
                    $tmp_dep = array_unique(search_app_dependency($depval, $db1));
                    if (!empty($tmp_dep)) {
                        foreach ($tmp_dep as $kkkkey => $vvvvalue) {
                            $newList[] = $vvvvalue;
                        }
                    }
                }
                if (!empty($newList)) {
                    $dependencies_final = array_unique($newList);
                    $newListTotal = array();
                    foreach ($newList as $mlist) {
                        if (!in_array($mlist, $functions_array)) {
                            $newListTotal[] = $mlist;
                        }
                    }

                    #$dependencies_less_functions=array_diff($dependencies_final,$functions_array);
                    $newListTotal = array_unique($newListTotal);
                    $dependencies = implode(",", $newListTotal);
                } else {
                    $dependencies = "";
                }
            }


            $var = $value->attributes()->name;
            if ($var != "") {
                $apps[] = "('$var','$functions','$dependencies')";
            }
        }

        if (count($apps) > 0) {
            $apps = array_unique($apps);
            $out = implode(",", $apps);
            $db1->query("INSERT INTO default_applications (name,functions,dependency) VALUES " . $out . ";");
        }

        $regions = array();
        foreach ($xml3->result->region->entry as $value) {
            $name = $value->attributes()->name;
            $help = $value->attributes()->{'help-string'};
            if ($name != "") {
                $regions[] = "('$name','$help')";
            }
        }
        if (count($regions) > 0) {
            $out = implode(",", $regions);
            $db1->query("INSERT INTO default_regions (name,help) VALUES " . $out . ";");
        }

//        $urls = array();
//        if (isset($xml5->result->{'pan-url-categories'})){
//            foreach ($xml5->result->{'pan-url-categories'}->entry as $value) {
//                $name = $value->attributes()->name;
//                if ($name != "") {
//                    $urls[] = "('$name')";
//                }
//            }
//        }
//        else{
//            foreach ($xml5->result->{'url-categories'}->entry as $value) {
//                $name = $value->attributes()->name;
//                if ($name != "") {
//                    $urls[] = "('$name')";
//                }
//            }
//        }
//
//        if (count($urls) > 0) {
//            $out = implode(",", $urls);
//            $db1->query("INSERT INTO default_url_categories (name) VALUES " . $out . ";");
//        }

        # Create default VIEW
        $db1->query("INSERT INTO config_views (view) VALUES ('panos');");

        $message = [
            'success'   => true,
            'msg'       => "Project $project created correctly.",
        ];
        return $message;
    }
}

class AppDependency{
    public $processed;

    public $container;
    public $implicit;
    public $name = '';
    public $technology;
    public $risk;
    public $category;
    public $subcategory;
    public $default_port;
    public $default_protocol;
    public $dependencies = array();
    public $evasive_behavior;
    public $consume_big_bandwidth;
    public $used_by_malware;
    public $able_to_transfer_file;
    public $has_known_vulnerability;
    public $tunnel_other_application;
    public $prone_to_misuse;
    public $pervasive_use;

    public $certifications;
    public $is_fedramp;
    public $is_hipaa;
    public $is_pci;
    public $is_soc1;
    public $is_soc2;
    public $is_ssae16;
    public $is_truste;
    public $is_data_breaches;
    public $is_ip_based_restrictions;
    public $is_poor_financial_viability;
    public $is_poor_terms_of_service;

    public function printMemberObject() {
        var_dump(get_object_vars($this));
    }

    public function dumpMemberObject() {
        get_object_vars($this);
    }

    public function __construct(
        $container,
        $implicit,
        $name,
        $technology,
        $risk,
        $category,
        $subcategory,
        $default_port,
        $default_protocol,
        $dependencies,
        $evasive_behavior,
        $consume_big_bandwidth,
        $used_by_malware,
        $able_to_transfer_file,
        $has_known_vulnerability,
        $tunnel_other_application,
        $prone_to_misuse,
        $pervasive_use,
        $ori_country,
        $issaas,
        $certifications,
        $is_fedramp,
        $is_hipaa,
        $is_pci,
        $is_soc1,
        $is_soc2,
        $is_ssae16,
        $is_truste,
        $is_data_breaches,
        $is_ip_based_restrictions,
        $is_poor_financial_viability,
        $is_poor_terms_of_service
    )
    {
        $this->container = $container;
        $this->implicit = $implicit;
        $this->name = $name;
        $this->technology = $technology;
        $this->risk = $risk;
        $this->category = $category;
        $this->subcategory = $subcategory;
        $this->default_port = $default_port;
        $this->default_protocol = $default_protocol;
        $this->dependencies = $dependencies;
        $this->evasive_behavior = $evasive_behavior;
        $this->consume_big_bandwidth = $consume_big_bandwidth;
        $this->used_by_malware = $used_by_malware;
        $this->able_to_transfer_file = $able_to_transfer_file;
        $this->has_known_vulnerability = $has_known_vulnerability;
        $this->tunnel_other_application = $tunnel_other_application;
        $this->prone_to_misuse = $prone_to_misuse;
        $this->pervasive_use = $pervasive_use;
        $this->ori_country = $ori_country;
        $this->issaas = $issaas;
        $this->processed = false;

        $this->certifications = $certifications;
        $this->is_fedramp = $is_fedramp;
        $this->is_hipaa = $is_hipaa;
        $this->is_pci = $is_pci;
        $this->is_soc1 = $is_soc1;
        $this->is_soc2 = $is_soc2;
        $this->is_ssae16 = $is_ssae16;
        $this->is_truste = $is_truste;
        $this->is_data_breaches = $is_data_breaches;
        $this->is_ip_based_restrictions = $is_ip_based_restrictions;
        $this->is_poor_financial_viability = $is_poor_financial_viability;
        $this->is_poor_terms_of_service = $is_poor_terms_of_service;


    }

//    public function __construct($name, ARRAY $depApps){
//        $this->name = $name;
//        $this->processed = false;
//        $this->dependencies = $depApps;
//    }

    public function addDependencies(ARRAY $depApps){
        $this->dependencies = array_merge($this->dependencies, $depApps);
        $this->dependencies = array_unique($this->dependencies);
    }

    public function getName(){
        return $this->name;
    }

    public function isProcessed(){
        return $this->processed;
    }

    public function setProcessed(){
        $this->processed = true;
    }

    public function getDependencies(){
        return $this->dependencies;
    }
}

function explode_app_dependency(&$dependenciesArray){

    foreach ($dependenciesArray as $app){
        $dependencies = $app->getDependencies();
        foreach($dependencies as $dependency) {  //If one of the dependencies is the current app itself, skip this dependency. It is a 1-level loop
            if($dependency == $app->getName()){
                continue;
            }
            $deps = expandDependencies($dependenciesArray, $dependency);
            $app->addDependencies($deps);
        }
    }

    return $dependenciesArray;
}

/*
function search_app_dependency_in_array_old($db1){
    $dependenciesArray = array();
    $getDep = $db1->query("SELECT id, name, dependency FROM default_applications");
    while ($row = $getDep->fetch_assoc()){
        $dependencies = explode(",", $row['dependency']);
        $id = $row['id'];
        $appName = $row['name'];
        if(count($dependencies) == 1 && $dependencies[0] == ""){
            $dependencies = array();
        }
        $app = new AppDependency($id, $appName, $dependencies);
        $dependenciesArray[$appName] = $app;
    }

    foreach ($dependenciesArray as $app){
        $dependencies = $app->getDependencies();
        foreach($dependencies as $dependency) {
            $deps = expandDependencies($dependenciesArray, $dependency);
            $app->addDependencies($deps);
        }
    }

    return $dependenciesArray;
}
*/

function expandDependencies(ARRAY &$dependenciesArray, String $dependencyIndex){
    if($dependencyIndex == ""){
        return null;
    }

    $appToExpand = $dependenciesArray[$dependencyIndex];
    if (!$appToExpand->isProcessed()){
        $appToExpand->setProcessed(); //Set it as processed even before processing, but after the check. This way we will break n-level loops.
        $dependencies = $appToExpand->getDependencies();
        foreach($dependencies as $dependency){
            $subDependencies = expandDependencies($dependenciesArray, $dependency);
            if($subDependencies) {
                $appToExpand->addDependencies($subDependencies);
            }
        }

    }
    return $appToExpand->getDependencies();
}

function search_app_dependency($currentList, $db1, $alreadyProcessed=array()) {
    $newList = array();
    $newList[] = $currentList;
//    echo "SELECT dependency FROM default_applications WHERE name='$currentList';";

    $getDep = $db1->query("SELECT dependency FROM default_applications WHERE name='$currentList';");
    if ($getDep->num_rows>0){
        $data = $getDep->fetch_assoc();
        $dependency = $data['dependency'];
        if ($dependency == "") {
            return $newList;
        } else {
            $new = explode(",", $dependency);
            foreach ($new as $kkey => $vvalue) {
                if(!in_array($vvalue, $alreadyProcessed)) {
                    $alreadyProcessed[] = $vvalue;
                    $tmp = search_app_dependency($vvalue, $db1, $alreadyProcessed);
                }
                else{
                    $tmp = [];
                }
                foreach ($tmp as $myvalue) {
                    $newList[] = $myvalue;
                }
            }
            return $newList;
        }
    }
    else{
        return $newList;
    }

}

function delete_Project($data){
    require_once INC_ROOT.'/userManager/API/projects/delete.php';
    if(isset($data['action']) && $data['action'] == "delete_all"){

        //MT-305: Disable project_backup
//        $message = checkBackupFolder();
//        if (!$message['code']){
//            $message = [
//                "code" => false,
//                "msg" => $message['msg']
//            ];
//        }
//        else {
            $deletedProjects = deleteAllProjects();
            $projects = array();
            foreach ($deletedProjects as $project) {
                delete_db_internal($project);
                $projects[] = $project;
            }
            $projectsName = implode(",", $projects);
            $message = [
                "code" => true,
                "msg" => "$projectsName have been deleted"
            ];
//        }
    }
    else {
//        $message = checkBackupFolder();
//        if (!$message['code']){
//            $message = [
//                "code" => false,
//                "msg" => $message['msg']
//            ];
//        }
//        else {
            $project = $data['name'];

            $message = deleteProject($project);

            if ($message['code']) {
                $message = delete_db($project);
            }
            else {
                $message = [
                    "code" => true,
                    "msg" => "You do not have permissions to delete the '$project' project. Contact your administrator."
                ];
            }
//        }
    }
    return $message;
}

function delete_db($project){
    $message = delete_db_internal($project);
    return $message;
}

// MT-305: Disable project_backup when deleting project
//function checkBackupFolder(){
//    $failed = false;
//    $messageError = array();
//    $messageError["code"] = false;
//    $messageError["msg"] = "The folder \"".USERSPACE_PATH."\" does not exist and/or the \"apache\" user does not have rights to Create it and write in it. <a target='#blank' href='/documentation/configuration/environment.php'>More info...</a>";
//
//    if(!file_exists(USERSPACE_PATH)){
//        error_reporting(E_ALL ^ E_WARNING | E_PARSE);
//        if(!mkdir(USERSPACE_PATH, 0770, true)){
//            $failed = true;
//        }
//        error_reporting(E_ALL | E_PARSE);
//    }
//    if($failed){
//        return $messageError;
//    }
//
//    if(!file_exists(USERSPACE_PATH."/ProjectBackups/")){
//        error_reporting(E_ALL ^ E_WARNING | E_PARSE);
//        if(!mkdir(USERSPACE_PATH.'/ProjectBackups', 0770, true)){
//            $failed = true;
//        }
//        error_reporting(E_ALL | E_PARSE);
//    }
//    if($failed){
//        return $messageError;
//    }
//
//    $message = array();
//    $message["code"] = true;
//    $message["msg"] = "Backup folder Exists";
//    return $message;
//}

//MT-305: Disable project_backup when deleting project
//function backupProject(STRING $project){
//    $PROJECTPATHCOMPLETE = USERSPACE_PATH."/projects/".$project."/";
//    exec('mysqldump --user='.DBUser.' --password='.DBPass.' '.$project.' > '.$PROJECTPATHCOMPLETE.'/'.$project.'_dump.sql');
//    $timeNow = time();
//    exec('tar -czf '. USERSPACE_PATH.'/ProjectBackups/'.$project.'_'.$timeNow.'.tar.gz --directory='.USERSPACE_PATH.'/projects '.$project);
//}

function delete_db_internal($project) {
    $db1 = new mysqli(DBServer, DBUser, DBPass);

    if ($db1->connect_error) {
        trigger_error('Database connection failed while deleting the db', E_USER_ERROR);
    }


    $PROJECTPATH = USERSPACE_PATH."/projects/";
    $PROJECTPATHCOMPLETE = $PROJECTPATH.$project."/";

    //MT-305: Disable project_backup when deleting project
    //Backup database and project into a ZIP file
    //    backupProject($project);

    //Perform the delete
    $sql = "DROP DATABASE " . $project;
    $db1->query($sql);
    if ($db1->error) {
        $message = array();
        $message["code"] = false;
        $message["msg"] = $db1->error;
        return $message;
    }
    else {
        $db1->select_db("pandb");
        $sql = "DELETE FROM projects WHERE name='$project';";
        $db1->query($sql);

        if (is_dir($PROJECTPATHCOMPLETE)) {
            rm_folder_recursively($PROJECTPATHCOMPLETE);
        }

        $getCrons = $db1->query("SELECT id, name, command FROM cronjobs WHERE project = '$project' AND disable = '0';");
        if ($getCrons->num_rows >= 1) {
            $all_command = "";
            while ($getCData = $getCrons->fetch_assoc()) {
                $name = $getCData['name'];
                $command = $getCData['command'];
                $all_command .= $command . "\n";
                exec('echo -e "`crontab -u www-data -l`\n' . $all_command . '" | crontab -', $output);
            }
        }
        else {
            // Delete all cron
            exec('echo -e "`crontab -r -u www-data`" | crontab -', $output);
        }

        // Delete CronJobs
        //$db2->select_db("pandb");
        $sql2 = "DELETE FROM cronjobs WHERE project = '$project';";
        $db1->query($sql2);

        $message = array();
        $message["code"] = true;
        $message["msg"] = "Project $project deleted correctly.";
        return $message;
    }
}

function rm_folder_recursively($dir) {
    foreach (scandir($dir) as $file) {
        if ('.' === $file || '..' === $file)
            continue;
        if (is_dir("$dir/$file"))
            rm_folder_recursively("$dir/$file");
        else
            unlink("$dir/$file");
    }
    rmdir($dir);
    return true;
}