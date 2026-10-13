<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 16/3/16 - 11:36
 */
namespace PaloAltoNetworks\Validation;

use Violin\Violin;
use PaloAltoNetworks\Sentinel\Role\Role;

class RoleValidator extends Violin
{
    protected $role;
    public function __construct(ROLE $role)
    {
        $this->role = $role;

        $this->addFieldMessages([
            'slug' => [
                'uniqueRoleSlug' => '<br>This <b>role code</b> is already taken',
                'required'       => '<br>Enter the <b>Role Name</b>'
            ],
            'name' => [
                'uniqueRoleName' => '<br>This <b>role name</b> is already taken',
                'required'       => '<br>Enter the <b>Role Name</b>'

            ],
            'permissions' => [
                'validCheck' => '<br>This field had an unexpected value'
            ],
            'project' => [
                'uniqueRoleSlug' => '<br>This <b>Project code</b> is already taken',
                'alnumDash'      => '<br>Only alphanumeric values are allowed for the <b>Project Name</b>',
                'max'            => '<br><b>Project name</b>\'s length too long',
                'required'       => '<br>Enter the <b>Project Name</b>'

            ],
            'device' => [
                'uniqueRoleSlug' => '<br>This <b>Device code</b> is already taken',
                'alnumDash'      => '<br>Only alphanumeric values are allowed for the <b>Device Serial number</b>',
                'max'            => '<br><b>Device Serial</b>\'s length too long',
                'required'       => '<br>Enter the <b>Device Serial</b>'

            ],
        ]);
    }

    public function validate_uniqueRoleSlug($value, $input, $args)
    {
        $user = $this->role->where('slug', $value); //Looks for a user in the table used in the Model User and returns it if found
        return ! (bool) $user->count();
    }

    public function validate_uniqueRoleName($value, $input, $args)
    {
        return ! (bool) $this->role->where('name', $value)->count();
    }

    public function validate_permissions($value, $input, $args)
    {
        return true;
    }

    public function validate_existsRoleName($value, $input, $args)
    {
        return (bool) $this->role->where('name', $value)->count();
    }

    public function validate_existsRoleSlug($value, $input, $args)
    {
        return (bool) $this->role->where('slug', $value)->count();
    }

}