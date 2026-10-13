<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 1/6/16 - 15:44
 */

namespace PaloAltoNetworks\AmqpWrapper;

////Loads all global PHP definitions
//require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';
//require_once INC_ROOT.'/userManager/start.php';

//require_once INC_ROOT.'/libs/vendor/autoload.php';
//require_once INC_ROOT.'/libs/vendor/php-amqplib/php-amqplib/PhpAmqpLib/Connection/AMQPStreamConnection.php';
//require_once INC_ROOT.'/libs/vendor/php-amqplib/php-amqplib/PhpAmqpLib/Message/AMQPMessage.php';

use PhpAmqpLib\Connection\AMQPStreamConnection;
use PhpAmqpLib\Message\AMQPMessage;

class SimpleSender
{

    public function execute($message)
    {
//        $my = fopen("senderDebug.txt","a");
//        fwrite($my, " : Open  : ". time()."\n");
        //$connection = new AMQPStreamConnection('localhost', 25672, 'MT4webserver', 'S3cur3C0nn3cti0n@');
        $rabbitHost = getenv('RABBITMQ_HOST') ?: '127.0.0.1';
        $connection = new AMQPStreamConnection(
            $rabbitHost,    #host - Docker Compose uses service name "rabbitmq"
            5672,           #port - port number of the service, 5672 is the default
            'guest',        #user - username to connect to server
            'guest'         #password
        );
//        fwrite($my, " : Opened: ". time()."\n");


        /** @var $channel AMQPChannel */
        $channel = $connection->channel();
//        fwrite($my, " : ChCrea: ". time()."\n");

        $channel->queue_declare(
            'jobs',    #queue name - Queue names may be up to 255 bytes of UTF-8 characters
            false,          #passive - can use this to check whether an exchange exists without modifying the server state
            false,           #durable - make sure that RabbitMQ will never lose our queue if a crash occurs - the queue will survive a broker restart
            false,          #exclusive - used by only one connection and the queue will be deleted when that connection closes
            false           #autodelete - queue is deleted when last consumer unsubscribes
        );
//        fwrite($my, " : ChDecl: ". time()."\n");

        $msg = new AMQPMessage(
                    $message,
                    array('delivery_mode' => 2) #make the message persistent
                   );
//        fwrite($my, " : MsgCre: ". time()."\n");

        $channel->basic_publish(
            $msg,           #message
            '',             #exchange
            'jobs'     #routing key
        );

//        fwrite($my, " : MsgSen: ". time()."\n");
        $channel->close();
//        fwrite($my, " : ChClos: ". time()."\n");
        $connection->close();
//        fwrite($my, " : Closed: ". time()."\n");
//        fclose($my);
    }
}