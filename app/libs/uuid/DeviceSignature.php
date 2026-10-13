<?php


namespace PaloAltoNetworks\expedition\utils;


class DeviceSignature
{
    public function __construct(){

    }

    static public function get():string{
        $machineIPsCommand=" ip a | sed '\|^ *inet[^ ]* |!d;s|||;s| .*||' | grep -v 127.0.0.1/8";
        $machineMACCommand=" ip a | sed '\|^ *link[^ ]* |!d;s|||;s| .*||' | grep -v 00:00:00:00:00:00";

        exec($machineMACCommand, $macs);
        exec($machineIPsCommand, $ips);

        return implode("-", array_merge($macs, $ips));
    }

}