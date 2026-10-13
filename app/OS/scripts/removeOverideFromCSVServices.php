<?php

$_SERVER['DOCUMENT_ROOT'] = '/var/www/html';
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT .'/userManager/API/accessControl_CLI.php';
require_once INC_ROOT.'/libs/common/tools/tools.php';

// ***************                   USER VARIABLES                   ***************
$projectName = 'cisco';  //Provide the project's name
$user = "admin"; // user to execute the script

// CODE STARTS HERE

class RemoveOverride
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
        take_snapshot_last($this->projectName);

    }

    public function execute(){


        if($this->error){
            echo $this->errorMessage."\n";
            exit(-1);
        }

        $query = "UPDATE services set override='' where override='no' and devicegroup='csv';";
        $this->projectDB->query($query);

        echo "\nScript finished\n";
        exit(1);

    }








}

global $app;
$params = [
    'user'  => $user
];
$executor = new RemoveOverride($projectName, $params);
$executor->execute();

