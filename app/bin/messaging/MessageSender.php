<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 9/6/16 - 10:06
 */

//Loads all global PHP definitions
require_once $_SERVER['DOCUMENT_ROOT'].'/libs/common/definitions.php';

//User management control
require_once INC_ROOT.'/userManager/start.php';
require_once INC_ROOT.'/bin/authentication/sessionControl.php';

require_once INC_ROOT.'/libs/PaloAltoNetworks/AmqpWrapper/SimpleSender.php';


use PaloAltoNetworks\AmqpWrapper\SimpleSender;

class MessageSender{

    protected $message;

    public function __construct($message)
    {
        $this->message = $message;
    }

    public function send(){
        $messageJSON = json_encode($this->message);
        $simpleSender = new SimpleSender();
        $simpleSender->execute($messageJSON);
    }

}