<?php
# Copyright (c) 2018 Palo Alto Networks, Inc.
# All rights reserved.

namespace PaloAltoNetworks\expedition\sns;
require_once INC_ROOT."/libs/uuid/DeviceSignature.php";
require_once '/var/www/html/libs/settings/PackageVersionChecker.php';
require_once INC_ROOT."/libs/utils.php";
require_once INC_ROOT.'/libs/projectdb.php';

define ('FEATURES',1);
define ('MIGRATION',1);

define ('ANALYSIS',2);
    define ('ML',1);
    define ('RE',2);
    define ('SPLUNK',3);
    define ('AUTOPROCESS',4);

define ('SEARCH_REPLACE',3);
define ('BULK_EDIT',4);


define ('CONTENT',2);
define ('RULES',1);
    define ('SEC',1);
    define ('NAT',2);
define ('OBJECTS',2);

use PaloAltoNetworks\expedition\utils\DeviceSignature;
use PackageVersionChecker;

define("TYPE_HELLO" , 'hello');
define("TYPE_MAKE_WISH" , 'mkwish');
define("TYPE_STATS" , 'stats');
define("SNS_API_URL" , 'https://expedition-notifications.panw.io/v1');
define("SNS_ENABLED" , True);
define("UUID_FILENAME" , USERSPACE_PATH."/.uuid5");
define("SIGNATURE_FILENAME" , USERSPACE_PATH."/.signatureMAC");
define("REPORTED_DATE" , USERSPACE_PATH."/.reportedDate");
define("SNS_OBJ" , 'None');
define("SNS_AVAILABLE" , False);
define("CPUID_FILENAME_SRC", '/sys/devices/virtual/dmi/id/product_uuid');
define("CPUID_FILENAME",USERSPACE_PATH."/.cpuid");


$packageVersionChecker = new PackageVersionChecker();
$message['msg'] = $packageVersionChecker->getExpeditionVersion();

define("EX_VERSION", $message['msg']['Expedition']);

class sns {
    protected $url;
    protected $init_ok;
    protected $uuid;
    protected $signature;
    protected $signature_ok;
    protected $version;

    /***
     * sns constructor.
     * @param array $params
     */
    public function __construct(ARRAY $params){
        $url= $params['url'] ?? SNS_API_URL;
        $this->url=$url;
        if (!isset($params["update"])){
            $params["update"]=false;
        }
        if ($params['update']===true &&
            file_exists(UUID_FILENAME) &&
            file_exists(SIGNATURE_FILENAME))
        {
            $signatureCheck = file_get_contents(SIGNATURE_FILENAME);
            $this->set_signature($signatureCheck);
            if(!$this->verifyMySignature()){
                $this->signature_ok = $this->reset_signature();
                $this->init_ok = $this->reset_uuid();
            }
        }
        else{
            $this->signature_ok = $this->reset_signature();
            $this->init_ok = $this->init_uuid();
        }
    }

    /***
     */
    public function periodicReportExpedition()
    {
        if(file_exists(REPORTED_DATE)) {
            $dateCheck = file_get_contents(REPORTED_DATE);
            if ($this->todayReported($dateCheck)){
                return;
            }
        }

        $uuid = file_get_contents(UUID_FILENAME);
        $this->set_uuid($uuid);
        $this->set_version(EX_VERSION);
        $this->init_ok = $this->update();
        //echo "$this->version for $uuid\n";
        $this->set_reported_date();
    }

    private function todayReported(string $date): bool
    {
        return $this->get_today() === $date;
    }

    private function set_reported_date()
    {
        $today = $this->get_today();
        file_put_contents(REPORTED_DATE, $today);
    }

    /***
     */
    public function reportExpedition()
    {
        $uuid = file_get_contents(UUID_FILENAME);
        $this->set_uuid($uuid);
        $this->set_version(EX_VERSION);
        $this->init_ok = $this->update();
    }

    public function get_status(): bool
    {
        return $this->init_ok;
    }

    private function set_uuid($uuid)
    {
        $this->uuid=$uuid;
    }

    private function set_signature($signature)
    {
        $this->signature = $signature;
    }

    private function set_version($version='1')
    {
        $this->version=$version;
    }

    private function get_uuid(){
        return $this->uuid;
    }

    private function get_version(){
        return $this->version;
    }

    private function validate_uuid($uuid): bool
    {
        $UUIDv4 = '/^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i';
        if (preg_match($UUIDv4, $uuid)){
            return TRUE;
        }

        return FALSE;
    }

    private function verifyMySignature():bool{
        $realSignature = DeviceSignature::get();
        return $this->signature === $realSignature;
    }

    /***
     * @return bool
     */
    private function reset_uuid(): bool
    {
        $uuid=uuid4();
        $this->set_uuid($uuid);
        $saved_file=file_put_contents(UUID_FILENAME, $uuid);
        if (($saved_file === false) || ($saved_file === -1)) {
            return FALSE;
        }
//        $cpuid=file_get_contents(CPUID_FILENAME_SRC);
//        $saved_file=file_put_contents(CPUID_FILENAME, $cpuid);
//        if (($saved_file === false) || ($saved_file == -1)) {
//            return FALSE;
//        }
        return $this->hello_world();
    }

    private function get_today():string
    {
        $command = 'date +%x';
        exec($command, $today);
        return $today[0];
    }

    private function reset_signature(): bool
    {
        $signature = DeviceSignature::get();
        $saved_file=file_put_contents(SIGNATURE_FILENAME, $signature);
        return !(($saved_file === false) || ($saved_file === -1));
    }

    /***
     * @return bool
     */
    private function update(): bool
    {
        return $this->send_stats("Update Installed");
    }

    /***
     * @return bool
     */
    private function init_uuid(): bool
    {
        $uuid_error = "01010101-0101-0101-0101-010101010101";
        $this->set_uuid($uuid_error);
        # Test case 1: UUID_FILENAME file does not exist. We try to create a new uuid and store in the filesystem
        $this->set_version(EX_VERSION);
        //if ((file_exists(UUID_FILENAME)) AND (file_exists(CPUID_FILENAME))){
        if (file_exists(UUID_FILENAME)) {
            $uuid=file_get_contents(UUID_FILENAME);

            # Check if its valid UUID v4
            if ($this->validate_uuid($uuid)){
                $this->set_uuid($uuid);
            }
            else{
                return FALSE;
            }
//            #Check if the CPUID has changed.
//            $cpuid=file_get_contents(CPUID_FILENAME);
//            $cpuidSrc=file_get_contents(CPUID_FILENAME_SRC);
//            if ($cpuid!==$cpuidSrc){
//                return $this->reset_uuid();
//            }
            return TRUE;
        }

        return $this->reset_uuid();
    }


    /***
     * @param $message
     * @return bool
     */
    private function send_message($message): bool
    {

        if ($message!==""){
            $ch = curl_init(SNS_API_URL);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT ,5);
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "POST");
            curl_setopt($ch, CURLOPT_POSTFIELDS, $message);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            /** @noinspection CurlSslServerSpoofingInspection */
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_HTTPHEADER, array(
                    'Content-Type: application/json',
                    'Content-Length: ' . strlen($message))
            );

            $result = curl_exec($ch);
            $resultJson= json_decode($result, true, 512);
            if ($resultJson['response']==="ok"){
                return TRUE;
            }
        }
        return FALSE;
    }

    /***
     * @return bool
     */
    private function hello_world(): bool
    {
        $uuid=$this->get_uuid();
        $version=$this->get_version();
        return $this->send_message('{"type": "'.TYPE_HELLO.'", "message": "Hello world!", "version":"'.$version.'", "uuid":"exp-'.$uuid.'"}');
    }

    /***
     * @param $stats
     * @return bool
     */
    public function send_stats($stats): bool
    {
        $uuid=$this->get_uuid();
        $version=$this->get_version();
        $telemetry = $this->get_stats();

        if($this->is_telemetry_enabled()) {
            $structure = [
                "type" => TYPE_STATS,
                "message" => json_encode($telemetry),
                "version" => "$version",
                "uuid" => "exp-" . $uuid
            ];
        }
        else {
            $structure = [
                "type" => TYPE_STATS,
                "message" => "$stats",
                "version" => "$version",
                "uuid" => "exp-" . $uuid
            ];
        }

        return $this->send_message(json_encode($structure));
//        return $this->send_message(
//            '{"type": "'.TYPE_STATS.'", "message":"'.$stats.'", "version":"'.$version.'", "uuid":"exp-'.$uuid.'"}');
    }

    private function is_telemetry_enabled():bool{
        if(!defined('TELEMETRY')){
            return true;
        }
        return TELEMETRY;
    }

    /***
     * @param $message
     * @return bool
     */
    public function make_wish($message): bool
    {
        $uuid=$this->get_uuid();
        $version=$this->get_version();
        return $this->send_message('{"type": "'.TYPE_MAKE_WISH.'", "message":"'.$message.'", "version":"'.$version.'", "uuid":"exp-'.$uuid.'"}');
    }


    public function get_stats(): array
    {
        $response = [];

        $number_projects = "SELECT vendors, created_at, name FROM pandbRBAC.projects;";

        if($pandbRBAC = selectDatabase('pandbRBAC')) {
            $projects_results = $pandbRBAC->query($number_projects);
            if ($projects_results->num_rows > 0) {
                while ($project_entry = $projects_results->fetch_assoc()) {
                    $project_name = $project_entry['name'];
                    $project_date = $project_entry['created_at'];
                    $response[$project_date][FEATURES][MIGRATION] = json_decode($project_entry['vendors'], true);
                    if ($project = selectDatabase($project_name)) {
                        $response[$project_date][FEATURES][ANALYSIS][ML] = $this->getML($project);
                        $response[$project_date][FEATURES][ANALYSIS][RE] = $this->getRE($project);
                        $response[$project_date][CONTENT][RULES][SEC] = $this->getSecRules($project);
                        $response[$project_date][CONTENT][RULES][NAT] = $this->getNatRules($project);
                        $response[$project_date][CONTENT][OBJECTS] = $this->getObjects($project);
                        $response[$project_date]['hash'] = md5(json_encode($response[$project_date]));
                    }
                }
            }
        }
        $response[0][FEATURES][ANALYSIS][AUTOPROCESS] = $this->autoprocessCSV();
        $response[0][FEATURES][ANALYSIS][SPLUNK] = $this->splunk_consumed();
        return $response;
    }

    private function getML(\mysqli $projectdb){
        $ML_query = "SELECT if(count(*)>0,'yes','no') as amount FROM ML_NewRules;";
        $ML_res = $projectdb->query($ML_query);
        if($ML_res->num_rows>0){
            $data = $ML_res->fetch_assoc();
            return $data['amount'];
        }
    }

    private function getRE(\mysqli $projectdb){
        $RE_query = "SELECT if(count(*)>0,'yes','no') as amount FROM ML_RuleEnrichment;";
        $res = $projectdb->query($RE_query);
        if($res->num_rows>0){
            $data = $res->fetch_assoc();
            return $data['amount'];
        }
    }

    private function getSecRules(\mysqli $projectdb){
        $sec_rules_query = "SELECT count(*) as amount FROM security_rules;";
        $res = $projectdb->query($sec_rules_query);
        if($res->num_rows>0){
            $data = $res->fetch_assoc();
            return $data['amount'];
        }
    }

    private function getNatRules(\mysqli $projectdb){
        $nat_rules_query = "SELECT count(*) as amount FROM nat_rules;";
        $res = $projectdb->query($nat_rules_query);
        if($res->num_rows>0){
            $data = $res->fetch_assoc();
            return $data['amount'];
        }
    }

    private function getObjects(\mysqli $projectdb){
        $objects_query = "SELECT sum(amount) as amount 
                            FROM (
                                    SELECT count(*) as amount FROM address UNION
                                    SELECT count(*) as amount FROM address_groups_id UNION
                                    SELECT count(*) as amount FROM services UNION
                                    SELECT count(*) as amount FROM services_groups_id 
                            ) t;";
        $res = $projectdb->query($objects_query);
        if($res->num_rows>0){
            $data = $res->fetch_assoc();
            return $data['amount'];
        }
    }

    private function splunk_consumed()
    {
        if(!$pandbRBAC = selectDatabase('pandbRBAC')){
            return 0;
        }
        $splunk_used = "SELECT if(count(*)>0,'yes','no') as amount FROM pandbRBAC.splunk_files;";
        $res = $pandbRBAC->query($splunk_used);
        if($res->num_rows>0){
            $data = $res->fetch_assoc();
            return $data['amount'];
        }
        return 0;
    }

    private function autoprocessCSV()
    {
        if(!$pandbRBAC = selectDatabase('pandbRBAC')){
            return 0;
        }
        $query = "SELECT if(count(*)>0,'yes','no') as amount FROM devices WHERE autoProcessCSV = 1;";
        $res = $pandbRBAC->query($query);
        if($res->num_rows>0){
            $data = $res->fetch_assoc();
            return $data['amount'];
        }
        return 0;
    }




}