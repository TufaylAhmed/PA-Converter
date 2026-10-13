<?php
namespace PaloAltoNetworks\expedition\utils;

use Exception;

class UUID4
{
    protected $isUpperCase;
    public function __construct($isUpperCase = false)
    {
        $this->isUpperCase = (bool)$isUpperCase;
    }

    /***
     * @param string $sep
     * @return string
     * @throws Exception
     */
    public function get(string $sep = '-'): string
    {
        $result = '';
        // time_low                     unsigned 32 bit integer
        $result .= $this->random(32);
        // "-"
        $result .= $sep;
        // time_mid                     unsigned 16 bit integer
        $result .= $this->random(16);
        // "-"
        $result .= $sep;
        // time_hi_and_version          unsigned 16 bit integer
        // version (0100)
        $result .= $this->hexString(1 << 2, 4);
        // time-hi
        $result .= $this->random(12);
        // "-"
        $result .= $sep;
        // clock_seq_hi_and_reserved    unsigned 8  bit integer
        // 10xxxxxx (x is random)
        $result .= $this->hexString(1 << 7 | random_int(0, (2 ** 6) - 1), 8);
        // clock_seq_low                unsigned 8  bit integer
        $result .= $this->random(8);
        // "-"
        $result .= $sep;
        // node                         unsigned 48 bit integer
        $result .= $this->random(48);
        return $result;
    }

    /***
     * @param $bitNum
     * @return string
     * @throws Exception
     */
    protected function random($bitNum): string
    {
        $result = '';
        $bits = 16;
        $sum = 0;
        while ($bitNum !== $sum && $bits > 0) {
            $bits = (($bitNum - $sum) > 16) ? 16 : $bitNum - $sum;
            $sum += $bits;
            $val = random_int(0, (2 ** $bits) -1);
            $result = $this->hexString($val, $bits) . $result;
        }
        return $result;
    }

    protected function hexString($val, $bits): string
    {
        $digits = (int) ($bits / 4 + 0.9);
        return sprintf('%0' . $digits . ($this->isUpperCase ? 'X' : 'x'), $val);
    }
}