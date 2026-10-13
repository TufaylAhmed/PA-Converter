<?php
// Instructions:
// 1. Copy this file into your Expedition VM on /var/www/html/OS/scripts
// 2. Edit the file using vi and edit the variables
// $project_name = The Expedition project name
// $config_name = The source file name
// $vsys = The vsys name
// $rule_names = An array containing the rules to query into the device, the script will do a call for each rule_name
// $device_key = The device API KEY
// $device_ip = The device IP
// $device_port = The device PORT, 443 by default
// $debug = if true will show the CURL debug information when doing the call to the device
// 3. Execute the script using sudo php /var/www/html/OS/scripts/get_hit_count_security_rule.php

$_SERVER['DOCUMENT_ROOT'] = '/var/www/html';
require_once $_SERVER['DOCUMENT_ROOT'] . '/libs/common/definitions.php';
require_once INC_ROOT . '/libs/projectdb.php';
require_once INC_ROOT . '/userManager/API/accessControl_CLI.php';
require_once INC_ROOT . '/libs/common/tools/tools.php';

// ***************                   USER VARIABLES                   ***************
// user to execute the script
$user = "admin"; // Keep this value
$project_name = '';  //Provide the project's name
$config_name = '';
$vsys = 'vsys1';
$rule_names = [
    'Allow Incoming',
    'Allow Outgoing',
];
$device_key = '';
$device_ip = '192.168.1.3';
$device_port = '443';
$debug = false;

// CODE STARTS HERE

class HitCountSecurityRule
{
    /* @var $projectName String */
    protected $projectName = '';

    /* @var mysqli $projectDB */
    protected $projectDB = null;
    protected $sourceID = 0;
    protected $vsys = "";
    protected $tables = [];
    protected $csvFile = "";
    protected $tag_name = "";

    protected $error = false;
    protected $errorMessage = '';
    protected $params = [];

    public function __construct(array $params)
    {
        global $app;

        if ($user = $app->container->sentinel->findByCredentials(['email' => $params['user']])) {
            $app->sentinel->login($user);
        } else {
            $this->error = true;
            $this->errorMessage = 'User not found';
        }

        $this->params = $params;
        $this->projectName = $params['project_name'];
        $this->projectDB = selectDatabase($this->projectName);
        echo "\n**** INIT SCRIPT ****\n";
        echo "\nAuto saving snapshot for rollback\n\n";
        take_snapshot_last($this->projectName);

    }

    private function toDateTime($unixTimestamp)
    {
        return date("Y-m-d H:m:s", $unixTimestamp);
    }

    private function get_hits_device($vsys, $rule_name, $ip, $port, $api_key, $debug = true)
    {

        $entry = [];

        // Command for the device
        $cmd = "&cmd=" . urlencode("<show><rule-hit-count><vsys><vsys-name><entry name='$vsys'><rule-base><entry name='security'><rules><list><member>$rule_name</member></list></rules></entry></rule-base></entry></vsys-name></vsys></rule-hit-count></show>");
        // Complete url
        $devicePath = "https://" . $ip . ":" . $port . "/api?type=op&async=yes" . $cmd;

        // Custom headers to be added
        $headers = array(
            'X-PAN-KEY: ' . $api_key,
            'Expect:'
        );

        $tuCurl = curl_init();

        if ($debug) {
            echo "\n **** DEBUG CONNECTION FOR RULE NAME: $rule_name \n\n";
        }

        curl_setopt($tuCurl, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($tuCurl, CURLOPT_URL, $devicePath);
        curl_setopt($tuCurl, CURLOPT_TIMEOUT, 400000); // number of seconds prior to a timeout
        curl_setopt($tuCurl, CURLOPT_VERBOSE, $debug);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($tuCurl, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($tuCurl, CURLOPT_RETURNTRANSFER, true);

        curl_exec($tuCurl);

        if ($debug) {
            echo "\n **** \DEBUG CONNECTION FOR RULE NAME: $rule_name \n\n";
        }

        $line = curl_multi_getcontent($tuCurl);

        if ($debug) {
            echo "\n **** Response: ****\n\n";
            echo "$line";
            echo "\n **** \Response: ****\n";
        }

        $xml = simplexml_load_string($line);
        $entry = $xml->xpath("//entry");

        unset($entry[0]);
        unset($entry[1]);

        foreach ($entry as $key => $value) {

            $rulehits = $value->{'hit-count'};
            $firsthit = $this->toDateTime(intval($value->{'first-hit-timestamp'}));
            $lastreset = $this->toDateTime(intval($value->{'last-reset-timestamp'}));
            $lasthit = $this->toDateTime(intval($value->{'last-hit-timestamp'}));

            echo "\n\n*** Rule: $rule_name";
            echo "\n\n\trulehits: $rulehits";
            echo "\n\tfirsthit: $firsthit";
            echo "\n\tlastreset: $lastreset";
            echo "\n\tlasthit: $lasthit\n";

            $entry['rulehits']=$rulehits;
            $entry['firsthit']=$firsthit;
            $entry['lastreset']=$lastreset;
            $entry['lasthit']=$lasthit;

        }

        curl_close($tuCurl);

        return $entry;

    }

    public function execute()
    {


        if ($this->error) {
            echo $this->errorMessage . "\n";
            exit(-1);
        }

        $vsys = $this->params['vsys'];
        // Get the source Id
        $source = "";
        $config_filename = $this->params['config_name'];
        $getSourceID = $this->projectDB->query("SELECT id FROM device_mapping WHERE filename='$config_filename' GROUP BY filename;");
        if ($getSourceID->num_rows == 1) {
            $data = $getSourceID->fetch_assoc();
            $source = $data['id'];
        }
        if ($source === "") {
            echo "\n Error: File name not found in the given project\n";
            exit(-1);
        }


        // Foreach of the given rules
        foreach ($this->params['rules'] as $rule_name) {

            // Get the rule
            $query = "SELECT id, name, description FROM security_rules where name = '$rule_name' and vsys='$vsys' and source = '$source'";

            $getRule = $this->projectDB->query($query);
            if ($getRule->num_rows == 1) {
                $data = $getRule->fetch_assoc();
                $rule_lid = $data['id'];

                echo "\n **** Processing new rule: ****\n";
                echo "\n\t Rule name= $rule_name \n\t Rule id= $rule_lid\n";


                // check the hitcount with the device
                $entry = $this->get_hits_device($vsys, $rule_name, $this->params['ip'], $this->params['port'], $this->params['key'], $this->params['debug']);

                $rulehits = $entry['rulehits'];
                $firsthit = $entry['firsthit'];
                $lastreset = $entry['lastreset'];
                $lasthit = $entry['lasthit'];

                $delete = "DELETE from security_rules_hits where rule_lid = '$rule_lid' and vsys = '$vsys' and source = '$source'";
                $this->projectDB->query($delete);

                $update = "INSERT into security_rules_hits (source, vsys, rule_name, rule_lid, hit_count, hit_last, hit_first, last_reset, created_at) values ('$source', '$vsys', '$rule_name', '$rule_lid' , '$rulehits', '$lasthit', '$firsthit' , '$lastreset' ,NOW()) ";
                $this->projectDB->query($update);

                echo "\n\t Rule updated\n";


            } else {
                echo "\n **** Rule with name $rule_name not found in the given project, skipping and getting next rule\n";
            }

        }


        echo "\nScript finished\n";
        exit(1);

    }


}

global $app;
$params = [
    'user' => $user,
    'project_name' => $project_name,
    'vsys' => $vsys,
    'rules' => $rule_names,
    'config_name' => $config_name,
    'ip' => $device_ip,
    'port' => $device_port,
    'key' => $device_key,
    'debug' => $debug,
];
$executor = new HitCountSecurityRule($params);
$executor->execute();

