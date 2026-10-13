<?php

/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace PaloAltoNetworks\Sentinel\User;

//use Illuminate\Database\Eloquent\Model as Eloquent;
use Cartalyst\Sentinel\Users\EloquentUser;

//class User extends Eloquent
class User extends EloquentUser
{
    protected $table = 'users';
    protected $fillable = [
        'email',
        'password',
        'permissions',
        'last_login',
        'first_name',
        'last_name',
        'created_at',
        'updated_at',
        'location_id',
        'location_type',
        'timezone',
        'active',
        'token'
    ];

    protected $hidden = ['password'];
    protected static $settingsModel = 'PaloAltoNetworks\Sentinel\UserSettingsInProject\UserSettingsInProject';

    public function getFullName()
    {
        if (!$this->first_name || !$this->last_name){
            return null;
        }

        return "{$this->first_name} {$this->last_name}";
    }

    public function getFullNameOrUsername(){
        return $this->getFullName() ?: $this->email;

    }

    public function getGravatarUrl( $options = [] )
    {
        $size = isset($options['size']) ?  $options['size'] : 45;
        return 'https://www.gravatar.com/avatar/' . md5($this->email). '?s='. $size . '&d=mm';
    }

    /**
     * The UserSettings relationship.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function settings(){
        return $this->belongsToMany(static::$settingsModel, 'user_settings', 'user_id', 'project_id')->withTimestamps();
    }

    public function getSettings(){
        return $this->settings;
    }

    public function getMyRole(STRING $projectName):array{
        /** @var  $generalRole string */
        /** @var  $projectRole string */
        if($superUser = $this->hasAnyAccess("user.create")){
            $generalRole = "Super User";
        }
        elseif($superUser = $this->hasAnyAccess("user.update")){
            $generalRole = "Admin";
        }
        elseif($superUser = $this->hasAnyAccess("user.view")){
            $generalRole = "User";
        }
        else{
            $generalRole = "invalid";
        }

        if($projectName!=''){
            if($superUser = $this->hasAnyAccess("projectRole.".$projectName.".admin")){
                $projectRole = "Admin";
            }
            elseif($superUser = $this->hasAnyAccess("projectRole.".$projectName.".update")){
                $projectRole = "User";
            }
            elseif($superUser = $this->hasAnyAccess("projectRole.".$projectName.".view")){
                $projectRole = "Viewer";
            }
            else{
                $projectRole = "No Role";
            }
        }
        else{
            $projectRole = "";
        }

        return [
            'generalRole'   => $generalRole,
            'projectRole'   => $projectRole
        ];
    }

}