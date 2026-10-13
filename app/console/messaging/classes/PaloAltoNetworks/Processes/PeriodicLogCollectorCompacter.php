<?php

require_once INC_ROOT.'/libs/common/device/CsvFilesProcesser.php';
use PaloAltoNetworks\Sentinel\Devices\CsvFilesProcesser;

require_once INC_ROOT.'/libs/projectdb.php';
require_once INC_ROOT.'/libs/objects/Response.php';
// require_once INC_ROOT.'/bin/projects/discovery/processCSVLogs.php';

class PeriodicLogCollectorCompacter
{

    private $parentJobID;
    private $sender;

    public function __construct(ARRAY $params){
        $this->parentJobID = $params['parentJobID'];
        $this->sender   = (isset($params['sender']))    ? $params['sender']     : null;
        $this->params   = $params;
    }

    public function log(String $msg, $level=1){
        require_once INC_ROOT.'/libs/common/MTLogger.php';
        $logger = (new MTLogger)->getInstance();
        $logger->log($msg, $level);
    }


    public function start(){
        $this->log(date(DATE_RFC2822)." Start Task", 0);
        $this->execute();
        $this->log(date(DATE_RFC2822)." End Task\n\n", 0);
    }

    public function execute()
    {
        $pandbRBAC = selectDatabase('pandbRBAC');

        $query = 'SELECT id, devicename, serial, afterProcess FROM devices WHERE autoProcessCSV=1 AND active=1';
        $results = $pandbRBAC->query($query);


        if($results->num_rows>0) {
            $parameters = array();
            while ($data = $results->fetch_assoc()) {

                //$parameters['project'] = isset($data['project'])? $data['project']:'';
//                $parameters['device'] = isset($data['serial']) ? $data['serial'] : '';
                $parameters['mode'] = isset($data['mode']) ? $data['mode'] : 'false';
//                $parameters['afterProcess'] = isset($data['afterProcess']) ? $data['afterProcess'] : null;

                $parameters['devices'][]= [
                    'serial'        => isset($data['serial']) ? $data['serial'] : '',
                    'afterProcess'  => isset($data['afterProcess']) ? $data['afterProcess'] : null
                ];

                //Call processing CSV logs from this device
                global $app;
                //Authenticate the user that set this scheduled task

//                $this->log("Checking CSV logs from device " . $parameters['device']);
//                $message = $this->processCSVLogs($parameters);  //$message contains the jobID in $message['msg']
//
//                if ($message->getSuccess() == false) {
//                    $this->log("    " . $message->toString());
//                    $this->log("");
//                    continue;
//                } else {
//                    $this->log("    CSV log(s) found. LogCoCo (Collector and Compacter) fired to process the CSV data. Job_id=" . $message->getCode());
//                    $this->log("");
//                }
            }
//            print_r($parameters);

             $deviceNames = array();
             foreach($parameters['devices'] as $device){
               $deviceNames[] = $device['serial'];
             }
             $this->log("Checking CSV logs from device(s) ". implode(" ,",$deviceNames));
             $message = $this->processCSVLogs($parameters);
            if ($message->getSuccess() == false) {
                $this->log("    " . $message->toString());
                $this->log("");
            } else {
                $this->log("    CSV log(s) found. LogCoCo (Collector and Compacter) fired to process the CSV data. Job_id=" . $message->getCode());
                $this->log("");
            }
        }
    }

    private function processCSVLogs(ARRAY $parameters):Response{
        $project = isset($parameters['project'])? $parameters['project']:'';
//        $serial = isset($parameters['device']) ? $parameters['device'] : '';
//        $mode = isset($parameters['mode']) ? $parameters['mode'] : 'false';
//        $afterProcess = isset($parameters['afterProcess']) ? $parameters['afterProcess'] : null;

        //Verify that the SparkRAM is defined.
        if(!defined('SparkRAM')){
            define('SparkRAM','1024m');
        }

        $csvProcesser = new CsvFilesProcesser($project, SparkRAM, json_encode($parameters), $this->parentJobID);

        return $csvProcesser->processCSVLogs($this->sender->id);
    }
}