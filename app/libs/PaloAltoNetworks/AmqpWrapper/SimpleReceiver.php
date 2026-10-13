<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 2/6/16 - 11:04
 */

namespace PaloAltoNetworks\AmqpWrapper;

if (function_exists('xdebug_disable')) {
    xdebug_disable();
}
error_reporting(E_ERROR | E_PARSE);

require_once INC_ROOT.'/userManager/API/accessControl_CLI.php';
require_once INC_ROOT.'/console/messaging/classes/PaloAltoNetworks/Processes/ClassLoader.php';
require_once INC_ROOT.'/console/messaging/classes/PaloAltoNetworks/Processes/PeriodicTask.php';
//require_once INC_ROOT."/libs/sns/sns.php";

//use PaloAltoNetworks\expedition\sns\sns;
use PhpAmqpLib\Connection\AMQPStreamConnection;
use PaloAltoNetworks\Processes\ClassLoader;
use PaloAltoNetworks\Processes\PeriodicTask;
use PhpAmqpLib\Exception\AMQPTimeoutException;

class SimpleReceiver
{
    /**
     * Listens for incoming messages
     */
    public function listen()
    {
        $rabbitHost = getenv('RABBITMQ_HOST') ?: 'localhost';
        $connection = new AMQPStreamConnection(
            $rabbitHost,    #host (Docker: rabbitmq service name)
            5672,           #port
            'guest',        #user
            'guest'         #password
        );

        $channel = $connection->channel();

        $channel->queue_declare(
            'jobs',    #queue name, the same as the sender
            false,          #passive
            false,          #durable
            false,          #exclusive
            false           #autodelete
        );

        $channel->basic_consume(
            'jobs',                    #queue
            '',                             #consumer tag - Identifier for the consumer, valid within the current channel. just string
            false,                          #no local - TRUE: the server will not send messages to the connection that published them
            true,                           #no ack - send a proper acknowledgment from the worker, once we're done with a task
            false,                          #exclusive - queues may only be accessed by the current connection
            false,                          #no wait - TRUE: the server will not respond to the method. The client should not wait for a reply method
            array($this, 'processOrder')    #callback - method that will receive the message
        );

        $params=array("update"=>true);

        //$counter = 0;
        while(count($channel->callbacks)) {
            try {
                $channel->wait(null, false, 30);
            }
            catch(AMQPTimeoutException $e) {
                //Check periodic task to perform
                $periodicTask = new PeriodicTask();
                $periodicTask->executePending();
                /* MT-2460 - Disabled call to Telemetry to avoid issues due to DNS timeout
                if($counter === 0) {
                    $reportVersion = new sns($params);
                    $reportVersion->periodicReportExpedition(); 
                    $counter++;
                }elseif($counter > 1999){
                    $counter = 0;
                }*/
            } catch (\ErrorException $e) {
                //Check periodic task to perform
                $periodicTask = new PeriodicTask();
                $periodicTask->executePending();
            }

            //TODO: Report alive every 30 seconds
        }

        $channel->close();
        $connection->close();
    }

    /**
     * @param $msg
     */
    public function processOrder($msgJSON)
    {
        $message = json_decode($msgJSON->body);
//        print_r($message);
         $loader = new ClassLoader($message);

    }
}