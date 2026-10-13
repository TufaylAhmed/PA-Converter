<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 18/5/16 - 16:26
 */

namespace PaloAltoNetworks\Validation;

use PaloAltoNetworks\Sentinel\Projects\Project;
use Violin\Violin;

class ProjectValidator extends Violin
{
    protected $project;

    public function __construct(Project $project)
    {
        $this->project = $project;

        $this->addFieldMessages([
            'name' => [
                'uniqueName' => '<br>This <b>Project Name</b> is already taken',
                'validName'  => '<br>This <b>Project name</b> is not valid',
                'required'   => '<br>Enter the project\'s <b>name</b>',
                'xssSave'    => 'This is not a valid name'
            ],
            'active' => [
                'isBoolean' => '<br><b>The Active</b> field should be a boolean'
            ],
            'tag' => [
                'xssSave' => 'This is not a valid description'
            ]
        ]);
    }

    public function validate_uniqueName($value, $input, $args)
    {
        $id = $args[0];
        $server = $this->project->where('name', $value)->where('id',"!=",$id);
        return ($server->count()== 0) ? true: false;
    }

    public function validate_isBoolean($value, $input, $args)
    {
        if ($value==0) return true;
        if ($value==1) return true;
        return false;
    }

    public function validate_validName($value, $input, $args){
        return ctype_alnum($value);
    }

    public function validate_xssSave($value, $input, $args){
        if($value != htmlspecialchars($value, ENT_QUOTES, 'UTF-8')){
            return false;
        }
        return true;
    }


}