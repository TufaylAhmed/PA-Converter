<?php

namespace Violin\Rules;

use Violin\Contracts\RuleContract;

class RegexnamewithbarRule implements RuleContract
{
    public function run($value, $input, $args)
    {
        $expression = "/^([0-9a-zA-Z]{1}([0-9a-zA-Z_-]|[ ]|[.])*)$/";
        return (bool) preg_match($expression, $value);
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
