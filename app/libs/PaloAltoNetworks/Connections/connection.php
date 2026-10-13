<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 15/6/16 - 17:12
 */

class CurlConnectionObject{
    public $curlConnection;
    public $hosts;
    public $origin;
    public $destination;

    public function __construct($name, $connection, $origin, $destination)
    {
        $this->name = $name;
        $this->curlConnection = $connection;
        $this->origin = $origin;
        $this->destination = $destination;
        $this->hosts = 1;
    }

    public function increase(){
        $this->hosts++;
    }

    public function decrease(){
        $this->hosts--;
    }

    public function isEmpty(){
        return (bool) $this->hosts<1;
    }

    public function isFull(){
        return (bool) $this->hosts>=25;
    }

}

function registerConnection(STRING $origin, STRING $destination){
    global $curlConnections;

    $position = $origin.'.'.$destination.'0';
    if(!isset($curlConnections[$position])){
        $tuCurl = curl_init();

        $position = $origin.'.'.$destination.'.0';
        $connection = new CurlConnectionObject($position, $tuCurl, $origin, $destination);
        $curlConnections[$position] = $connection;
    }
    else{
        $connection = $curlConnections[$position];
        if($connection->isFull()){
            $tuCurl = curl_init();
            $position = $origin.'.'.$destination.'0';
            $connection = new CurlConnectionObject($position, $tuCurl, $origin, $destination);
            $curlConnections[$position] = $connection;
        }
    }

//    echo "register:";
//    var_dump($curlConnections);

    return $connection;
}

function unregisterConnection(STRING $connectionName){
    global $curlConnections;

//    $connection = $curlConnections[$connectionName];
//
//    $connection->decrease();
//    echo "unregister:";
//    var_dump($curlConnections);
//
//    if($connection->isEmpty()) {
//        curl_close($connection->curlConnection);
//        unset($curlConnections[$connectionName]);
//    }
}