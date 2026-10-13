<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/


namespace PaloAltoNetworks\HealthCheck;

require_once INC_ROOT.'/libs/PaloAltoNetworks/HealthCheck/CheckResponse.php';

abstract class HealthCheck
{
    protected static $instance = null;

    /** @var string  */
    protected $className;

    /** @var string */
    protected $description;

    public function __construct(){
        $this->className = get_class($this);
        $this->description = $this->getDescription();
    }

    protected function __clone()
    {
    }

    abstract public function getDescription():string;

    abstract public function getCategory():string;

    abstract public function check():CheckResponse;

    abstract public function repair():CheckResponse;

    public static function getInstance()
    {
        if (!isset(static::$instance)) {
            static::$instance = new static;
        }
        return static::$instance;
    }

}