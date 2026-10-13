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
$projectName = 'MT2536';  //Provide the project's name
$source = '1229-SJRA2-show-running-config.txt'; //Provide the source's name
$user = 'admin'; //user executing the script
$csvFile = '/home/userSpace/address.csv'; // file containing the list of objects by name
$tag_name = 'TEST3'; // tag name to be added to listed objects


// ***************                   /USER VARIABLES                   ***************
$objects = [   //Determine the objects that are going to be processed
    'address',
    'address_groups_id',
    //'services', 'services_groups_id',
    //'tag',
    //'regions',
    //'applications', 'applications_filters', 'applications_groups_id'
];

// CODE STARTS HERE

class AddTag
{
    /* @var $projectName String */
    protected $projectName = '';

    /* @var mysqli $projectDB */
    protected $projectDB = null;
    protected $sourceID = 0;
    protected $vsys = "";
    protected $tables=[];
    protected $csvFile = "";
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

        $this->tables = $params['objects'];
        $this->csvFile = $params['csvFile'];
        $this->tag_name = $params['$tag_name'];

        $this->projectName= $name;
        $this->projectDB = selectDatabase($this->projectName);
        take_snapshot_last($this->projectName);

        $query = "SELECT id, vsys FROM device_mapping WHERE device = '".$params['sourceName']."' ORDER BY ID LIMIT 1;";
        $results = $this->projectDB->query($query);
        if($results->num_rows>0){
            $entry = $results->fetch_assoc();
            $this->sourceID = $entry['id'];
            $this->vsys = $entry['vsys'];
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

        //Step 1- Read given CSV file with named objects
        $object_names = $this->readCSVFile();

        //Step 2- Get the ids from the given named objects
        $ids_map = [];
        foreach ($this->tables as $table){
            $ids_map[$table] = $this->getID($table, $object_names);
        }

        //Step 3- Create or get the TAG id
        $tagId = $this->getOrCreateTAG();

        //Step 4- Assign the TAG to the got objects in step 2
        foreach ($this->tables as $table){
                $this->createTAGRelation($table, $tagId, $ids_map[$table]);
        }

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

    private function createTAGRelation(string $table_name, string $tag_id, array $ids){

        $tag_relations = [];
        foreach ($ids as $id){
            $tag_relations[] = "('$table_name','$id','$tag_id')";
        }

        if (count($tag_relations)>0){
            echo "\nAdding TAG[$this->tag_name] to [$table_name] objects";
            $exec = $this->projectDB->query("INSERT INTO tag_relations (table_name ,member_lid,tag_id) VALUES ".implode(",",$tag_relations).";");
            echo "\n\t" . $this->projectDB->info;
            unset($tag_relations);
        }

    }

    private function readCSVFile(){

        $file_content= file_get_contents($this->csvFile);
        return explode(PHP_EOL, $file_content);
    }

    private function getID(String $table, array $object_names): array
    {
        $ids = [];

        // Build string containing the names with slashed
        $imploded_object_names = "";
        foreach ($object_names as $name){
            if($name != ""){
                if($imploded_object_names=="") {
                    $imploded_object_names .= "'" . $name . "'";
                }else{
                    $imploded_object_names .= ", '" . $name . "'";
                }
            }
        }

        $query = "SELECT id FROM $table WHERE source = '".$this->sourceID."' and vsys= '".$this->vsys."' and name in ($imploded_object_names)";

        $result = $this->projectDB->query($query);
        if($result->num_rows>0) {
            while($entry = $result->fetch_assoc()) {
                $ids[] = $entry['id'];
            }
        }
        return $ids;
    }

}

global $app;

$params = [
    'user'  => $user,
    'sourceName' => $source,
    'objects'    => $objects,
    'csvFile' => $csvFile,
    '$tag_name' => $tag_name
    ];
$executor = new AddTag($projectName, $params);
$executor->execute();

