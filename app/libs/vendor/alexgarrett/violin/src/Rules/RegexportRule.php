<?php

namespace Violin\Rules;

use Violin\Contracts\RuleContract;

class RegexportRule implements RuleContract
{
    public function run($value, $input, $args)
    {
        $valid = false;
        $expression = "/^([0-9]{1}([0-9]|[-]|[,])*)$/";
        if ( (bool) preg_match($expression, $value)){
            $valid = true;
            $expression2 = "/^(?<start>[0-9]{1}([0-9])*)-(?<end>[0-9]{1}([0-9])*)$/";
            if( (bool) preg_match($expression2, $value, $outputArray)){
                if($outputArray['start']>$outputArray['end']){
                    $valid = false;
                }
            }
        }


        return $valid;
    }

    public function error()
    {
        return '{field} was not in the correct format.';
    }

    public function canSkip()
    {
        return true;
    }
}
