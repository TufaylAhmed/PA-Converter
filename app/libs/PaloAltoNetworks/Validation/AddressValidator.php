<?php
/**
 * Created by PhpStorm.
 * User: didacgil
 * Date: 8/3/16
 * Time: 13:59
 */
namespace PaloAltoNetworks\Validation;

use Violin\Violin;


class AddressValidator extends Violin
{
    protected $address;

    public function __construct()
    {
        $this->addFieldMessages([
            'id' => [
                'number' => '<br>It must be a number.'
            ],
            'name' => [
                'regexnamewithbar' => '<br>A valid object name must start with an alphanumeric character and can contain zero or more alphanumeric characters, underscore _, hyphen -, dot ., / or spaces',
                'required'  => '<br>Enter the name.</b>'
            ],
            //'description' => [
            //    'alnum'   => ''
            //],
            'type' => [
                'ipType' =>   '<br>The Type is incorrect.',
                'required' => '<br>This field is required.</b>'
            ],
            'ipaddress' => [
                'regexipaddressv4v6' => '<br>The IP Address or FQDN are incorrect.',
                'required'       => '<br>This field is required.</b>'
            ],
            'cidr' => [
                'number' => '<br>It must be a number.'
            ],
            //'names_tags' => [
            //    'alnum'  => '<br>Enter Tags.'
            //],


        ]);

    }

    public function validate_regexipaddressv4v6($value, $input, $args)
    {
        if($args[0]=='ip-netmask') {
            $response = (filter_var($value, FILTER_VALIDATE_IP) !== false);
            if ($response) {
                return true;
            }
        }

        if($args[0]=='ip-range') {
            $output_array = preg_split('/[\s|-]+/', $value); //Checking it has a - with spaces if existing
            if (count($output_array) == 2) { //Verify it has two range limits
                $response1 = (filter_var($output_array[0], FILTER_VALIDATE_IP) !== false); //Verify the first is an IP
                $response2 = (filter_var($output_array[1], FILTER_VALIDATE_IP) !== false); //Verify the second is an IP
                if ($response1 && $response2) return true;
            }
        }

        if($args[0]=='fqdn'){
            $regex = "/(?=^.{1,254}$)(^(?:(?!\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)*(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)/";
            echo json_encode(
                [
                    'regex'=> $regex,
                    'value'=>$value
                ]
            );
            if (preg_match($regex, $value, $output_array)==1){
                return true;
            }
        }

        return false;
    }

    public function validate_ipType($value, $input, $args){
        switch ($value){
            case "ip-netmask":
            case "ip-range":
            case "fqdn":
            case "dynamic":
            case "ip-wildcard":
                return true;
            default:
                return false;
        }
    }



}