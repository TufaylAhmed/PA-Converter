<?php
/**
 * Created by PhpStorm.
 * User: didacgil
 * Date: 8/3/16
 * Time: 13:59
 */
namespace PaloAltoNetworks\Validation;

use Violin\Violin;


class NameValidator extends Violin
{
    protected $address;

    public function __construct()
    {
        $this->addFieldMessages([
            'name' => [
                'regexName' => '<br>A valid object name must start with an alphanumeric character and can contain zero or more alphanumeric characters, underscore _, hyphen -, dot ., / or spaces',
                'required'  => '<br>Enter the name.</b>'
            ],

        ]);

    }

    public function validate_regexName($value, $input, $args)
    {
        //$expression = base64_decode($args[0]);
        $expression = "/^([0-9a-zA-Z]{1}([0-9a-zA-Z_-]|[ ]|[.]|[\/])*)$/";
        return (bool) preg_match($expression, $value);
    }


}