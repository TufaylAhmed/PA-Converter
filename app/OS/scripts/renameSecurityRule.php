<?php

$_SERVER['DOCUMENT_ROOT'] = '/var/www/html';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
require_once INC_ROOT.'/libs/common/tools/tools.php';

// ***************                   USER VARIABLES                   ***************
$projectName = 'project_name';  //Provide the project's name
$user = "admin"; // user to execute the script

// CODE STARTS HERE

class RenameSecurityRule
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


        $this->projectName= $name;
        $this->projectDB = selectDatabase($this->projectName);
        echo "\n Auto saving snapshot\n";
        take_snapshot_last($this->projectName);

    }

    public function execute(){


        if($this->error){
            echo $this->errorMessage."\n";
            exit(-1);
        }



        $query = "SELECT id, name, description FROM security_rules where description != ''";
        $rules = $this->projectDB->query($query);
        $duplicated_names = [];
        $ok="";
        $ko="";
        while($rule = $rules->fetch_assoc()){
            if(isset($rule['description']) && $rule['description']!=''){
                $new_name = substr($rule['description'], 0, 60);
                $id=$rule['id'];
                $name=$rule['name'];
                if (in_array($new_name, $duplicated_names)) {
                    $ko.="Rule id $id - Not renamed as new name is duplicated -  $new_name\n";
                }else{
                    $duplicated_names[]=$new_name;
                    $update = "UPDATE security_rules set name = '$new_name' where id = '$id';";
                    $this->projectDB->query($update);
                    $ok.="Rule id $id - Renamed from $name to $new_name\n";
                }

            }
        }
        echo "\nRenamed rules\n";
        echo $ok;
        echo "\nNot renamed rules\n";
        echo $ko;

        echo "\nScript finished\n";
        exit(1);

    }








}

global $app;
$params = [
    'user'  => $user
];
$executor = new RenameSecurityRule($projectName, $params);
$executor->execute();

