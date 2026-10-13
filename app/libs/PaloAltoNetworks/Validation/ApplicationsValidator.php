<?php
/**
 * Created by PhpStorm.
 * User: didacgil
 * Date: 8/3/16
 * Time: 13:59
 */
namespace PaloAltoNetworks\Validation;

use Violin\Violin;


class ApplicationsValidator extends Violin
{
    public function __construct()
    {
        $this->addFieldMessages([
            'id' => [
                'number' => '<br>It must be a number.'
            ],
            'name' => [
                'regexname' => '<br>A valid object name must start with an alphanumeric character and can contain zero or more alphanumeric characters, underscore _, hyphen -, dot ., / or spaces',
                'required'  => '<br>Enter the name.</b>'
            ],
            'parent_app' => [
                'regexname' => '<br>A valid object parent_app must start with an alphanumeric character and can contain zero or more alphanumeric characters, underscore _, hyphen -, dot ., / or spaces'
            ],
            'subcategory' => [
                'regexname' => '<br>A valid object subcategory must start with an alphanumeric character and can contain zero or more alphanumeric characters, underscore _, hyphen -, dot ., / or spaces',
                'required'  => '<br>Enter the Subcategory.</b>'
            ],
            'technology' => [
                'regexname' => '<br>A valid object technology must start with an alphanumeric character and can contain zero or more alphanumeric characters, underscore _, hyphen -, dot ., / or spaces',
                'required'  => '<br>Enter the Technology.</b>'
            ],
            'category' => [
                'regexname' => '<br>A valid object category must start with an alphanumeric character and can contain zero or more alphanumeric characters, underscore _, hyphen -, dot ., / or spaces',
                'required'  => '<br>Enter the Category.</b>'
            ],
            'risk' => [
                'number' => '<br>It must be a number.'
            ],
            'timeout' => [
                'number' => '<br>It must be a number.'
            ],
            'tcp_timeout' => [
                'number' => '<br>It must be a number.'
            ],
            'udp_timeout' => [
                'number' => '<br>It must be a number.'
            ],
            'tcp_half_closed_timeout' => [
                'number' => '<br>It must be a number.'
            ],
            'tcp_time_wait_timeout' => [
                'number' => '<br>It must be a number.'
            ],
            'ip_protocol_value' => [
                'number' => '<br>It must be a number.'
            ],
            'icmp_type' => [
                'number' => '<br>It must be a number.'
            ],
            'icmp_code' => [
                'number' => '<br>It must be a number.'
            ],
            'icmp6_type' => [
                'number' => '<br>It must be a number.'
            ],
            'icmp6_code' => [
                'number' => '<br>It must be a number.'
            ],
            'able_to_transfer_file' => [
                'alpha' => '<br>It must be a alpha.'
            ],
            'has_known_vulnerability' => [
                'alpha' => '<br>It must be a alpha.'
            ],
            'pervasive_use' => [
                'alpha' => '<br>It must be a alpha.'
            ],
            'consume_big_bandwidth' => [
                'alpha' => '<br>It must be a alpha.'
            ],
            'used_by_malware' => [
                'alpha' => '<br>It must be a alpha.'
            ],
            'prone_to_misuse' => [
                'alpha' => '<br>It must be a alpha.'
            ],
            'tunnel_other_application' => [
                'alpha' => '<br>It must be a alpha.'
            ],
            'evasive_behavior' => [
                'alpha' => '<br>It must be a alpha.'
            ],
            'tunnel_applications' => [
                'alpha' => '<br>It must be a alpha.'
            ],
            'file_type_ident' => [
                'alpha' => '<br>It must be a alpha.'
            ],
            'virus_ident' => [
                'alpha' => '<br>It must be a alpha.'
            ],
            'spyware_ident' => [
                'alpha' => '<br>It must be a alpha.'
            ],
            'data_ident' => [
                'alpha' => '<br>It must be a alpha.'
            ],

        ]);

    }

}