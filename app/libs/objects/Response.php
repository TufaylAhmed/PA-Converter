<?php
/*******************************************************************************
 * Copyright (c) 2018 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 2/25/19 11:55 AM
 ******************************************************************************/

require_once INC_ROOT.'/libs/objects/Messages.php';

class Response{
    public $success;
    public $messageCode;
    public $messageStruct;

    public function __construct(bool $success, int $messageCode, Messages $messageStruct)
    {
        $this->success = $success;
        $this->messageCode = $messageCode;
        $this->messageStruct = $messageStruct;
    }

    public function getMessages():array{
        return $this->messageStruct->getMessages();
    }

    public function getMessagesString():String{
        return implode(", ", $this->getMessages());
    }

    public function getSuccess():bool {
        return $this->success;
    }

    public function getCode():int{
        return $this->messageCode;
    }

    public function __toString():String
    {
        if($this->messageCode ==0){
            return 'Success: '.$this->messageCode;
        }else{
            return 'Success: '.$this->messageCode.' Errors: '.$this->messageStruct->toString();
        }
    }

    public function toString():String{
        return $this->__toString();
    }
}