<?php

/***
 * This scrip performs the following tasks:
 * Step 1- For all objects in the Shared DG, set them as primary objects for later merge
 * Step 2- Move all the other objects into the Shared DG
 * Step 3- Merge all the objects (by name and value)
 * Step 4- Deletes all unused objects
 */
$_SERVER['DOCUMENT_ROOT'] = '/var/www/html';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';

// ***************                   USER VARIABLES                   ***************
$projectName = 'BigPanorama';  //Provide the project's name
$source = 'BiGPanorama_12345432111234.xml';
$user = 'admin';

$objects = [   //Determine the objects that are going to be processed
    'address',
    //'address_groups_id',
    //'services', 'services_groups_id',
    //'tag',
    //'regions',
    //'applications', 'applications_filters', 'applications_groups_id'
];



//*************** Set to true for each step to be performed *************************
$performStep1 = true;
$performStep2 = true;
$performStep3 = true;
$performStep4 = true;

//*************************** Specific step parameters ******************************
// STEP 1
$step1Params = [
    'primary_DG' => 'shared', //We want all the objects in DG shared to become primary objects to retain them when merged
];
// STEP 2
$step2Params = [];

// STEP 3
$step3Params = [
    'merge_by' => "name and value", //Options "name", "value", "name and value";
];

// STEP 4
$step4Params = [];



// CODE STARTS HERE

class MyScript1
{
    /* @var $projectName String */
    protected $projectName = '';

    /* @var mysqli $projectDB */
    protected $projectDB = null;
    protected $sourceID = 0;

    protected $step1;
    protected $step1Params;

    protected $step2;
    protected $step2Params;
    protected $step3;
    protected $step3Params;
    protected $step4;
    protected $step4Params;

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
        $this->projectName= $name;
        $this->projectDB = selectDatabase($this->projectName);

        $query = "SELECT id FROM device_mapping WHERE device = '".$params['sourceName']."' ORDER BY ID LIMIT 1;";
        $results = $this->projectDB->query($query);
        if($results->num_rows>0){
            $entry = $results->fetch_assoc();
            $this->sourceID = $entry['id'];
        }
        else{
            $this->error=true;
            $this->errorMessage = 'Error trying to identify the source. Please verify the name or contact fwmigrate@paloaltonetworks.com for assistance';
        }


        $this->step1 = (isset($params['step1']))?$params['step1']: true;
        $this->step2 = (isset($params['step2']))?$params['step2']: true;
        $this->step3 = (isset($params['step3']))?$params['step3']: true;
        $this->step4 = (isset($params['step4']))?$params['step4']: true;
        $this->step1Params = (isset($params['step1Params']))?$params['step1Params']: [];
        $this->step2Params = (isset($params['step2Params']))?$params['step2Params']: [];
        $this->step3Params = (isset($params['step3Params']))?$params['step3Params']: [];
        $this->step4Params = (isset($params['step4Params']))?$params['step4Params']: [];
    }

    public function execute(){
        require_once INC_ROOT.'/libs/common/tools/tools.php';

        if($this->error){
            echo $this->errorMessage."\n";
            exit(-1);
        }

        //Step 1- For all objects in the Shared DG, set them as primary objects for later merge
        if ($this->step1) {
            $this->setAsPrimary();
        }

        //Step 2- Move all the other objects into the Shared DG
        if ($this->step2) {
            $this->moveToShared();
        }

        //Step 3- Merge all the objects (by name and value)
        if ($this->step3) {
            $this->mergeObjects();
        }

        //Step 4- Deletes all unusued objects
        if ($this->step4) {
            $this->deleteUnused();
        }
    }

    /***
     * Returns a set of tabs to normalize lines
     * @param String $name
     * @return string
     */
    private function getTabs(String $name): string{
        if (strlen($name) < 7) return  "\t\t\t\t";
        elseif (strlen($name) < 14) return "\t\t\t";
        elseif (strlen($name) < 21) return "\t\t";
        elseif (strlen($name) < 28) return "\t";
    }

    /***
     * Executes an SQL query to set certain objects to Primary
     * @param array $params
     * @return bool
     */
    private function updateToPrimary(ARRAY $params):bool{
        $table_name = $params['table_name'];
        $source = $params['source'];
        $vsys = $params['vsys'];

        $query= "UPDATE $table_name SET merge_as_primary = '1' WHERE vsys='$vsys' AND source='$source'";
        $this->projectDB->query($query);

        if($this->projectDB->affected_rows>0){
            return true;
        }
        else{
            return false;
        }

    }

    /***
     * Iterates on all the selected object types and sets them to Primary if they fit in the right source and DG
     * @return bool
     */
    private function setAsPrimary(): bool{
        //Get all the objects from the provided vsys/DG
        $vsys = isset($this->step1Params['primary_DG'])? $this->step1Params['primary_DG'] : 'shared';

        foreach ($this->tables as $table) {
            $tabs = $this->getTabs($table);
            $query = "SELECT id FROM $table WHERE vsys = '$vsys' \n";
            $results = $this->projectDB->query($query);
            if($this->projectDB->affected_rows>0){
                $ids = [];
                while($entry = $results->fetch_assoc()){
                    $ids[] = $entry['id'];
                }

                $params = [
                    'table_name' => "$table",
                    'merge_as_primary_id' => implode(",", $ids),
                    'vsys' => $this->step1Params['primary_DG'],
                    'source' => $this->sourceID
                ];
                $response = $this->updateToPrimary($params);

                if($response)
                    echo " $table $tabs objects in $vsys have been set as primary\n";
                else
                    echo " $table $tabs objects in $vsys have not been set as primary. This may be fine if there are no objects that fit this criteria\n";
            }
        }

        return true;
    }

    /***
     * Iterates on all the selected object types and moves them to Shared
     * @return bool
     */
    private function moveToShared(): bool
    {
        foreach ($this->tables as $table) {
            $tabs = $this->getTabs($table);

            $source = $this->sourceID;
            $query= "UPDATE $table SET vsys = 'shared' WHERE vsys!='shared' AND source='$source'";
            $this->projectDB->query($query);

            if($this->projectDB->affected_rows>0){
                echo " $table $tabs objects moved to Shared\n";
            }
            else{
                echo " $table $tabs objects not moved to Shared. This may be fine if there are no objects that fit this criteria\n";
            }
        }

        return true;
    }

    /***
     * Returns a default array with all the parameters set to false (criteria for merge)
     * @return array
     */
    private function resetMergeParams(): array{
        return [
            'vsys' => 'shared',
            'source'=> $this->sourceID,
            'selection' => [],
            'cons_address_name'=> false,
            'cons_address_name_value'=> false,
            'cons_address_value'=> false,
            'cons_addressgroups_name'=> false,
            'cons_addressgroups_name_value'=> false,
            'cons_addressgroups_value' => false,
            'cons_addressgroups_selection'=> false,
            'cons_services_name'=> false,
            'cons_services_name_value'=> false,
            'cons_services_value'=> false,
            'cons_servicesgroups_name'=> false,
            'cons_servicesgroups_name_value'=> false,
            'cons_servicesgroups_value'=> false,
            'cons_servicesgroups_selection'=> false,
            'cons_regions_name'=> false,
            'cons_regions_name_value'=> false,
            'cons_regions_value'=> false,
            'cons_tags_name'=> false,
            'cons_appgroups_name'=> false,
            'cons_appgroups_name_value'=> false,
            'cons_appgroups_value'=> false,
            'cons_app_name'=> false,
            'cons_appfilters_name'=> false
        ];
    }

    /***
     * Modifies the $params array to set to true the assigned table and given the user's merge criteria
     * @param array $params
     * @param string $table
     * @return array
     */
    private function correctParams(ARRAY &$params, string $table ){
        switch ($table){
            case 'address':
                if($this->step3Params['merge_by'] == "name and value"){
                    $params['cons_address_name_value'] = true;
                }elseif($this->step3Params['merge_by'] == "name"){
                    $params['cons_address_name'] = true;
                }elseif($this->step3Params['merge_by'] == "value"){
                    $params['cons_address_value'] = true;
                }
                break;

            case 'address_groups_id':
                if($this->step3Params['merge_by'] == "name and value"){
                    $params['cons_addressgroups_name_value'] = true;
                }elseif($this->step3Params['merge_by'] == "name"){
                    $params['cons_addressgroups_name'] = true;
                }elseif($this->step3Params['merge_by'] == "value"){
                    $params['cons_addressgroups_value'] = true;
                }
                break;

            case 'services':
                if($this->step3Params['merge_by'] == "name and value"){
                    $params['cons_services_name_value'] = true;
                }elseif($this->step3Params['merge_by'] == "name"){
                    $params['cons_services_name'] = true;
                }elseif($this->step3Params['merge_by'] == "value"){
                    $params['cons_services_value'] = true;
                }
                break;

            case 'services_groups_id':
                if($this->step3Params['merge_by'] == "name and value"){
                    $params['cons_servicesgroups_name_value'] = true;
                }elseif($this->step3Params['merge_by'] == "name"){
                    $params['cons_servicesgroups_name'] = true;
                }elseif($this->step3Params['merge_by'] == "value"){
                    $params['cons_servicesgroups_value'] = true;
                }
                break;

            case 'tag':
                $params['cons_tags_name'] = true;
                break;

            case 'regions':
                if($this->step3Params['merge_by'] == "name and value"){
                    $params['cons_regions_name_value'] = true;
                }elseif($this->step3Params['merge_by'] == "name"){
                    $params['cons_regions_name'] = true;
                }elseif($this->step3Params['merge_by'] == "value"){
                    $params['cons_regions_value'] = true;
                }
                break;

            case 'applications':
                $params['cons_app_name'] = true;
                break;

            case 'applications_filters':
                $params['cons_appfilters_name'] = true;
                break;

            case 'applications_groups_id':
                if($this->step3Params['merge_by'] == "name and value"){
                    $params['cons_appgroups_name_value'] = true;
                }elseif($this->step3Params['merge_by'] == "name"){
                    $params['cons_appgroups_name'] = true;
                }elseif($this->step3Params['merge_by'] == "value"){
                    $params['cons_appgroups_value'] = true;
                }
                break;

            default:
                break;
        }
    }


    private function getIDs(String $table){
        $ids = [];
        $query = "SELECT id FROM $table WHERE source = '".$this->sourceID."'";
        $result = $this->projectDB->query($query);
        if($result->num_rows>0) {
            while($entry = $result->fetch_assoc()) {
                $ids[] = $entry['id'];
            }
        }
        return $ids;
    }


    /***
     * Iterates on all the selected object types and merges them give then provided criteria
     * @return bool
     */
    private function mergeObjects(): bool{
        foreach ($this->tables as $table) {
            echo "Starting to merge $table\n";
            $tabs = $this->getTabs($table);

            $params = $this->resetMergeParams();
            $this->correctParams($params, $table);

            $params['selection'] = $this->getIDs($table);

            $response = setMergeObjects($this->projectName,  $params);

            if($response['code']){
                echo " $table $tabs objects have been merged\n";
            }
            else{
                echo " $table $tabs objects have not been merged. This may be fine if there are no objects that fit this criteria\n";
            }
        }

        return true;
    }

    private function deleteUnused(): bool{
        //TODO
        return true;
    }
}

global $app;

$params = [
    'user'  => $user,
    'sourceName' => $source,
    'objects'    => $objects,
    'step1' => $performStep1,
    'step2' => $performStep2,
    'step3' => $performStep3,
    'step4' => $performStep4,
    'step1Params' => $step1Params,
    'step2Params' => $step2Params,
    'step3Params' => $step3Params,
    'step4Params' => $step4Params,
    ];
$executor = new MyScript1($projectName, $params);
$executor->execute();

//

