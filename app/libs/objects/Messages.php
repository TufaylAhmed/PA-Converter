<?php
/*******************************************************************************
 * Copyright (c) 2018 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 2/25/19 11:55 AM
 ******************************************************************************/


class Messages{
    public $messages = array();

    public function __construct(array $message = [])
    {
        $this->messages = $message;
    }

    public function addMessage(String $message){
        $this->messages[] = $message;
    }

    public function getMessages():array{
        return $this->messages;
    }

    public function __toString():String
    {
        $messages = array();
        foreach ($this->messages as $message){
            $messages[] = $message;
        }

        return implode(" ", $messages);
    }

    public function toString():String{
        return $this->__toString();
    }
}