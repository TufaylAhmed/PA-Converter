<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 30/6/16 - 16:17
 */

class MTLogger{
    private static $instance = NULL;

    public function getInstance() {
        if(self::$instance === NULL) {
            self::$instance = new MTLogger();
        }
        return self::$instance;
    }

    public function log(String $msg, $level=1){
        $lines = explode(PHP_EOL,$msg);
        foreach ($lines as $line){
            for($i=0; $i<$level; $i++){
                echo "\t";
            }
            echo "$line\n";
        }
    }
}