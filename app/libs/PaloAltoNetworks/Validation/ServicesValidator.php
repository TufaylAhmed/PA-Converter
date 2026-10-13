<?php
/**
 * Created by PhpStorm.
 * User: didacgil
 * Date: 8/3/16
 * Time: 13:59
 */
namespace PaloAltoNetworks\Validation;

use Violin\Violin;


class ServicesValidator extends Violin
{
    protected $address;

    public function __construct()
    {
        $this->addFieldMessages([
            'id' => [
                'number' => '<br>It must be a number.'
            ],
            'name' => [
                'regexname' => '<br>A valid object name must start with an alphanumeric character and can contain zero or more alphanumeric characters, underscore _, hyphen -, dot ., / or spaces',
                'required'  => '<br>Enter the name.</b>'
            ],
            'sport' => [
                'regexport' => '<br>The Source Port are incorrect. It must be a number or valid increasing range.'
            ],
            'dport' => [
                'regexport'   => '<br>The Destination Port are incorrect. It must be a number or valid increasing range.',
                'required' => '<br>This field is required.</b>'
            ],
            'protocol' => [
                'alpha' => '<br>It must be a alpha.',
                'required' => '<br>This field is required.</b>'
            ],
            'timeout_tcp' => [
                'number' => '<br>Timeout-tcp must be a number.'
            ],
            'timeout_udp' => [
                'number' => '<br>Timeout-tcp must be a number.'
            ],
            'halfclose_timeout' => [
                'number' => '<br>Half-close Timeout must be a number.'
            ],
            'timewait_timeout' => [
                'number' => '<br>Time-wait Timeout must be a number.'
            ],
            'override' => [
                'alpha' => '<br>Override must be a alphanumeric.'
            ],
        ]);

    }


}