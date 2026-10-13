<?php
/*******************************************************************************
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by Didac Gil de la Iglesia (dgildelaig@paloaltonetworks.com)
 * Date: $today.year.hour.minute
 ******************************************************************************/
namespace PaloAltoNetworks\Expedition\Security;

use Noodlehaus\Exception;

require_once INC_ROOT.'/libs/Security/OpenSSLTools.php';

abstract class SecureObject{

    public function __construct(){
    }

    abstract public function secure(STRING $object);

    /***
     * Recursive listing files within a folder (path)
     * @param string $dir
     * @param string $skipFilesFormat
     * @return array
     */
    protected function dirToArray(STRING $dir, ARRAY $skipFilesFormat=array()) {
        $result = array();
        if(!is_null($dir) && $dir != ''){
            if(is_dir("$dir".DIRECTORY_SEPARATOR)) {
                $cdir = scandir($dir);
                if (is_array($cdir) && !is_null($cdir)) {
                    foreach ($cdir as $key => $value) {
                        if (!in_array($value, array(".", ".."))) {
                            if (is_dir($dir . DIRECTORY_SEPARATOR . $value)) {
                                $result = array_merge($result, $this->dirToArray($dir . DIRECTORY_SEPARATOR . $value, $skipFilesFormat));
                            }
                            else {
                                $list = array();
                                foreach ($skipFilesFormat as $format) {
                                    $list = array_merge($list, glob($dir . DIRECTORY_SEPARATOR . "$format"));
                                }
                                if (!in_array($dir . DIRECTORY_SEPARATOR . $value, $list)) {
                                    $result[] = $dir . DIRECTORY_SEPARATOR . $value;
                                }
                            }
                        }
                    }
                }
            }
        }
        return $result;
    }
}


