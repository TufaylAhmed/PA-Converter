<?php

namespace Violin\Rules;

use Violin\Contracts\RuleContract;

class RegexRule implements RuleContract
{
    public function run($value, $input, $args)
    {
        //$expression = base64_decode($args[0]);
        return (bool) preg_match($args[0], $value);
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
