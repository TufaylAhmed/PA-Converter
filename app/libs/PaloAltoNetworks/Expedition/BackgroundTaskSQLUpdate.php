<?php

namespace PaloAltoNetworks\Expedition;

require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
require_once INC_ROOT.'/libs/database.php';

class BackgroundTaskSQLUpdate extends BackgroundTask
{
    /* @var \mysqli */
    protected $dbName;

    protected $query;

    public function run() {
//        $this->dbConnection->query($this->query);
//        $this->output = $this->dbConnection->affected_rows;
//        $this->report();
        $fileName = "/tmp/executingSql".microtime(true).".sql";
        $myFile= fopen($fileName,"w");
        fwrite($myFile, $this->query);
        fclose($myFile);

        $mysql_file= create_mysql_file($this->filename);
        $command = "mysql --defaults-extra-file=$mysql_file $this->dbName < $fileName > /dev/null & echo $!";
        //$command = "mysql -u".DBUser." -p".DBPass." ".$this->dbName.
        //            " < $fileName ".  //Input file
        //            "> /dev/null & ". //Output to /dev/null so it continues running in background
        //            "echo $!";  //Get the pid
        //echo $command."\n";
        exec($command, $output);

        if(count($output)) {
            $this->pid = $output[0];
        }else{
            $this->pid = -1;
        }

        //echo "Pid = $this->pid \n";
        unlink($fileName);
    }

    function __construct(array $input) {
        parent::__construct($input);
        $this->query = $this->input['query'];
        $this->dbName = $this->input['dbName'];
    }

    function getResult(){
        return $this->output;
    }


}