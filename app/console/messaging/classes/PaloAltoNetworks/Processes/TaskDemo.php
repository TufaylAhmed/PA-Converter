<?php
/**
 * Created by PhpStorm.
 * User: dgildelaig
 * Date: 17/11/16
 * Time: 15:06
 */
//Place here the libraries that you may require for this specific Task
require_once INC_ROOT."/console/messaging/classes/PaloAltoNetworks/Processes/BestPractices/BestPracticeResults.php";
require_once INC_ROOT.'/libs/projectdb.php';

//Make sure that the class is named EQUALLY to the php file. Notice this file is called TaskDemo, therefore the class is called TaskDemo
//This is critical, as the AutoLoader will load the PHP file in order to be able to find the required class.
class TaskDemo
    extends AbstractProcess  //This class makes use of an Abstract parent Class, that has some general methods and specific controls.
                             //Always define your class as an extension of AbstractProcess
{

    //your class will always have this contrust method, that will ALWAYS get the parameters as an Array. The class loader is in charge
    //of passing these parameters. Those are the parameters that came from the JSON message. Additionally, it includes the user->id as a "sender" parameter
    public function __construct(ARRAY $params){
        parent::__construct($params);
    }

    //OPTIONAL
    //You can define internal methods that you want to use in this task logic
    private function isOdd($number){
        if ($number % 2 == 0) return true;
        return false;
    }

    //This method is mandatory. This will be called to execute the logic of the task. No more methods are required, but you may include methods that can be
    //locally called in this class.
    public function execute()
    {
        //Call the AbstractProcess::execute. This will validate that the current task has not been cancelled or rescheduled for the future
        if(!parent::execute()){
            return; //AbstractProcess::execute reported that this task does not need to be executed
        }

        //Required fields for final Task reporting: setCompleted, setFailed, etc.
        $errors = array();
        $errorMsg = array();
        $completeResult = array();

        $this->setStarted(); //Required to report this task is in process. This avoids multiple agents running the same task.

        $params = $this->params; //Collect the parameters for running this task
        $taskId = $params['taskId'];
        $data = $params['data'];

        //Validate we have all the needed parameters to run this task. For instance that you got the parameters "project" and "id".
        //This is custom specific for your task.
        if (!isset($data->project) OR (!isset($data->id))){
            $errors[] = -1;
            $errorsDev[] = "Param Project or RemediateID is missing";
        }
        else {
            //Task logic comes here
            $project = $data->project;
            //Tasks report/log into /home/userSpace/panReadOrders.log
            //Call the log method to present relevant information regarding this task execution
            //This method can be called as much as you want. But try not to overload the log file
            $this->log("Action:\t\tThis is a TaskDemo\n" .
                "Check:\t\tIt actually does Nothing\n" .
                "Project:\t" . $project
            );

            $numbers = array(1, 3, 5, 9);
            foreach ($numbers as $number) {
                if ($this->isOdd($number)) {
                    $completeResult[] = "This is an odd number. All is fine";
                } else {
                    // DO NOT call setFailed within the task logic. Reporting is done ONCE at the end.
                    $errors[] = "-1"; //Task had an error. Specify the error code here
                    $errorMsg[] = "The number $number is not an odd number. We have an error"; //Task had an error. Specify the error message here
                }
            }
        }

        if(count($errors) == 0){
            $this->setCompleted(implode(',',implode(',',$completeResult)));
        }
        else{
            $this->setFailed("There were problems applying the Best Practices GeneralSettings1: [".implode(',', $errorMsg)."]", implode(',', $errors));
        }
    }
}