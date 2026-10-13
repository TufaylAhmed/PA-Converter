<?php

/***
 * This scrip performs the following tasks:
 * Step 1- Read given CSV file with named objects
 * Step 2- Get the ids from the given named objects
 * Step 3- Create or get the TAG id
 * Step 4- Assign the TAG to the loaded objects in step 2
 */
$_SERVER['DOCUMENT_ROOT'] = '/var/www/html';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
require_once INC_ROOT.'/libs/common/tools/tools.php';

// ***************                   USER VARIABLES                   ***************
$projectName = 'Marco';  //Provide the project's name
$source = 'panos-REXT01-ruleset-converted.xml'; //Provide the source's name
$vsys = "vsys1";
$user = 'admin'; //user executing the script
$tag_name = 'MY_TEST_WITH_MARCO'; // tag name to be added to listed objects


// CODE STARTS HERE

class AddTag
{
    /* @var $projectName String */
    protected $projectName = '';

    /* @var mysqli $projectDB */
    protected $projectDB = null;
    protected $sourceID = 0;
    protected $device = "";
    protected $vsys = "";
    protected $tables=[];
    protected $tag_name = "";

    protected $error=false;
    protected $errorMessage='';

    public function __construct(string $name, array $params)
    {
        global $app;

        if($user = $app->container->sentinel->findByCredentials(['email' => $params['user']])) {
            $app->sentinel->login($user);
        }
        else{
            $this->error=true;
            $this->errorMessage='User not found';
        }

        $this->tag_name = $params['tag_name'];

        $this->projectName= $name;
        $this->projectDB = selectDatabase($this->projectName);
        take_snapshot_last($this->projectName);

        $this->device = $params['sourceName'];
        $this->vsys = $params['vsys'];

        $query = "SELECT id, vsys FROM device_mapping WHERE device = '".$params['sourceName']."' ORDER BY ID LIMIT 1;";
        $results = $this->projectDB->query($query);
        if($results->num_rows>0){
            $entry = $results->fetch_assoc();
            $this->sourceID = $entry['id'];
        }
        else{
            $this->error=true;
            $this->errorMessage = 'Error trying to identify the source. Please verify the name or contact fwmigrate@paloaltonetworks.com for assistance';
        }

    }

    public function execute(){


        if($this->error){
            echo $this->errorMessage."\n";
            exit(-1);
        }

        $tagId = $this->getOrCreateTAG();


        $query = $this->projectDB->query("SELECT distinct nat.position as nat_position, nd.rule_lid as nat_rule_lid, nat.name as nat_rule_name, nat.is_dat as dnat_type, sd.rule_lid as sec_rule_lid, r.name as sec_rule_name
                FROM nat_rules_dst nd, 
                security_rules_dst sd,
                security_rules r,
                nat_rules nat
                where nat.is_dat > 0
                and sd.member_lid = nd.member_lid 
                and sd.table_name = nd.table_name
                and sd.rule_lid = r.id
                and nat.id = nd.rule_lid
                order by nat.position;");
        while ($data = $query->fetch_assoc()) {
            $rule_ids[]=$data['sec_rule_lid'];
        }

        $rule_ids = array_unique($rule_ids);

        $this->createTAGRelation($tagId, $rule_ids);

        echo "\nScript finished\n";
        exit(1);

    }

    private function getOrCreateTAG(): string{
        $thecolor = 42;
        $exists = $this->projectDB->query("SELECT id FROM tag WHERE name IN ('$this->tag_name') AND source='$this->sourceID' AND vsys='$this->vsys';");
        if ($exists->num_rows !== 1) {
            $tag_color = "color".$thecolor;
            $this->projectDB->query("INSERT INTO tag (name_ext,name,color,vsys,source,devicegroup, used) VALUES ('$this->tag_name','$this->tag_name','$tag_color','$this->vsys','$this->sourceID','default',1);");
            $tagId = $this->projectDB->insert_id;
            echo "\nTAG [$this->tag_name] created";
        }
        else{
            echo "\nTAG [$this->tag_name] already exists";
            $data = $exists->fetch_assoc();
            $tagId = $data['id'];
        }
        return $tagId;
    }

    private function createTAGRelation(string $tag_id, array $ids){

        $tag_relations = [];
        foreach ($ids as $id){
            //"source, member_lid, table_name, rule_lid, vsys, devicegroup"
            $tag_relations[] = "('". $this->sourceID ."',".
                                "'". $tag_id. "',".
                                "'tag',".
                                "'".$id."',".
                                "'".$this->vsys."',".
                                "'".$this->device."'".
                                ")";
        }

        if (count($tag_relations)>0){
            echo "\nAdding TAG[$this->tag_name] to rules: " . implode(", ", $ids);
            $query = "INSERT INTO security_rules_tag (source, member_lid, table_name, rule_lid, vsys, devicegroup) VALUES ".implode(",",$tag_relations).";";
            //echo "\n". $query;
            $exec = $this->projectDB->query($query);
            echo "\n\t" . $this->projectDB->info;
            echo "\n\t" . $this->projectDB->error;
            //echo "\n\t" . $this->projectDB->get_warnings();
            unset($tag_relations);
        }

    }


}

global $app;

$params = [
    'user'  => $user,
    'sourceName' => $source,
    'tag_name' => $tag_name,
    'vsys' => $vsys,
    ];
$executor = new AddTag($projectName, $params);
$executor->execute();

