<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/

define('AdoesNotIntersectB',  -1); //          a=10.0.0.0/24,              b=192.168.0.0/24,
define('AisPartiallyInB',     10); //            a=10.0.0.10-10.0.0.0.20     b=10.0.0.5-10.0.0.0.15
define('AisPartiallyInBLow',  11); //         a=10.0.0.1-10.0.0.0.10      b=10.0.0.5-10.0.0.0.15
define('AisPartiallyInBHigh', 12); //        a=10.0.0.10-10.0.0.0.20     b=10.0.0.5-10.0.0.0.15
define('AisinB',               1); //A is in B            a=10.0.1.0/24               b=10.0.0.0/16
define('BisinA',               2); //B is in A            a=10.0.0.0/16               b=10.0.1.0/24

define('AltB',                -2); //A is smaller than B  a=10.0.0.0/24,              b=192.168.0.0/24,
define('AgtB',                 3); //A is bigger than B   a=192.168.0.0/24,           b=10.0.0.0/24,

?>