<?php


require_once INC_ROOT . "/libs/uuid/UUID4.php";

use PaloAltoNetworks\expedition\utils\UUID4;
//use PaloAltoNetworks\expedition\sns\sns;

function uuid4($isUpperCase = false, $separator = '-')
{
    return (new UUID4($isUpperCase))->get($separator);
}


function sns_init($params){

    //$obj = new sns($params);
    //$obj->reportExpedition();
    //echo $obj->get_status();

}