<?php
/*******************************************************************************
 * Copyright (c) 2018 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: 2/25/19 4:44 PM
 ******************************************************************************/

class Location {
    /**
     * @var int $amount
     * @var string $name
     * @var string $table_name
     */
    public $type = "zones";
    public $amount=0;
    public $riskAmount=0;
    public $name;
    public $table_name;

    public function __construct(String $name, String $table_name)
    {
        $this->table_name = $table_name;
        $this->name = $name;
    }

    public function setAmount(int $amount){
        $this->amount = $amount;
    }

    public function setRiskAmount(int $amount){
        $this->riskAmount = $amount;
    }

    public function getAmount():int{
        return $this->amount;
    }

    public function getName():String{
        return $this->name;
    }

    public function getType():String{
        return $this->type;
    }

    public function getTable_name():String{
        return $this->table_name;
    }

    public function getAmount_RiskAmount(): array{
        return [
            "amount"=>$this->amount,
            "riskAmount"=>$this->riskAmount,
            "objectType"=>$this->getType(),
            "locationType"=>$this->table_name,
        ];
    }
}