<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 30/6/16 - 11:25
 */
define ('Correct', 'Correct');
define ('ERROR_ConnectionNotEstablished', 'ConnectionNotEstablished');
define ('ERROR_NotExpectedFileFormat', 'NotExpectedFileFormat');
define ('ERROR_FileNotCreated', 'FileNotCreated');
define ('ERROR_ActionNotPossible', 'ActionNotPossible');
define ('ERROR_SpecificPANOS', 'SpecificPANOS');

function getErrorCode($error, $param = 'code' ){
    $ERROR_Codes['Correct']['code']                             = 0;
    $ERROR_Codes['Correct']['description']                      = 'No errors';

    //Logic errors
    $ERROR_Codes['ActionNotPossible']['code']                   = -1;
    $ERROR_Codes['ActionNotPossible']['description']            = 'This action is not possible for this context';

    //Connection errors
    $ERROR_Codes['ConnectionNotEstablished']['code']            = -10;
    $ERROR_Codes['ConnectionNotEstablished']['description']     = 'Connection Not Established with the destination';

    //File and File Format Errors
    $ERROR_Codes['FileNotCreated']['code']                      = -100;
    $ERROR_Codes['FileNotCreated']['description']               = 'The file was not created';
    $ERROR_Codes['NotExpectedFileFormat']['code']               = -101;
    $ERROR_Codes['NotExpectedFileFormat']['description']        = 'The retrieved file does not have the right file format';

    //Other errors
    $ERROR_Codes['SpecificPANOS']['code']                       = -500;
    $ERROR_Codes['SpecificPANOS']['description']                = 'PANOS has responded with errors';

    $ERROR_Codes['ERROR_NotGivenAPIKEY']['code']                = -501;
    $ERROR_Codes['ERROR_NotGivenAPIKEY']['description']         = 'APIKEY not provided';


    switch($param){
        case 'description':
        case 'code':
            return $ERROR_Codes[$error][$param];

        default:
            return $ERROR_Codes[$error]['code'];
            break;
    }
}