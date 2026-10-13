<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

namespace PaloAltoNetworks\HealthCheck;


class CheckResponse{
    /** @var bool  */
    private $successful;

    /** @var INT  */
    private $code;

    /** @var STRING  */
    private $msg;

    /** @var STRING  */
    private $remediation;

    /** @var HealthCheck  */
    private $check;


    public function __construct(HealthCheck $check, BOOL $successful, INT $code, STRING $msg, STRING $remediation )
    {
        $this->successful = $successful;
        $this->code = $code;
        $this->msg = $msg;
        $this->check = $check;
        $this->remediation = $remediation;

    }

    public function success():bool {
        return $this->successful;
    }

    public function code():int{
        return $this->code;
    }

    public function msg():string{
        return $this->msg;
    }

    public function remediation():string{
        return $this->remediation;
    }

    public function toJson():string{
        return json_encode([
                'code' => $this->code,
                'success'  => $this->successful==true?1:-1,
                'msg'   => $this->msg()]
        );
    }

    public function toArray():array{
        return [
            'category'  => $this->check->getCategory(),
            'check' => get_class($this->check),
            'code' => $this->code,
            'success'  => $this->successful,
            'msg'   => $this->msg(),
            'remediation'   => $this->remediation(),
            'description'   => $this->check->getDescription(),
        ];
    }
}