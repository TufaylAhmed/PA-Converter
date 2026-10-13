<?php

define ('VMSERIES','vm-series');
define ('PA200', 'pa200');
define ('PA220', 'pa220');
define ('PA400', 'pa400');
define ('PA500', 'pa500');
define ('PA800', 'pa800');
define ('PA820', 'pa820');
define ('PA850', 'pa850');
define ('PA2000','pa2000');
define ('PA3000','pa3000');
define ('PA3200','pa3200');
define ('PA4000','pa4000');
define ('PA5000','pa5000');
define ('PA5200','pa5200');
define ('PA5220','pa5220');
define ('PA5250','pa5250');
define ('PA5400','pa5400');
define ('PA5260','pa5260');
define ('PA7000','pa7000');

define ('M100','m100');
define ('M200','m200');
define ('M500','m500');
define ('M600','m600');
define ('VMPANORAMA','vm-panorama');


$pan_panorama = array(VMPANORAMA, M100, M200, M500, M600);
$pan_panorama_numbers = array('panorama', '100', '200', '500', '600');

$pan_virtual = array(VMSERIES, VMPANORAMA);

function getPanFw(){
    return array(VMSERIES, PA200, PA220, PA400, PA500, PA800, PA820, PA850, PA2000, PA3000, PA3200, PA4000, PA5000, PA5200, PA5220, PA5250, PA5260, PA5400, PA7000);
}

function getPanFwNumbers(){
    return array('vm',     '200', '220', '400', '500', '800', '820', '850', '2000', '3000', '3200', '4000', '5000', '5200', '5220', '5250', '5260', '5400', '7000');
}