<?php
/**
 * Copyright (c) 2017 Palo Alto Networks, Inc.
 * All rights reserved.
 *
 * Created by didacgil
 * Date: 18/5/16 - 16:07
 */

namespace PaloAltoNetworks\Sentinel\Devices;

use Illuminate\Database\Eloquent\Model as Eloquent;
//use Cartalyst\Sentinel\Sentinel;

class Device extends Eloquent
{
    protected $table = 'devices';
    protected $fillable = [
        'devicename',
        'hostname',
        'port',
        'type',
        'description',
        'active',
        'panos',
        'threats',
        'apps',
        'ispanorama',
        'config',
        'serial',
        'serialHA',
        'vsys',
        'appversion',
        'appreleasedate',
        'threatversion',
        'threatreleasedate',
        'device',
        'management',
        'urldb',
        'wildfireversion',
        'uptime',
        'deactivated',
        'connected',
        'created_at',
        'updated_at',
        'avversion',
        'urlfilteringversion',
        'logtype',
        'csv_path',
        'avoidToday',
        'afterProcess',
        'autoProcessCSV'
    ];


    /**
     * The Eloquent project model name.
     *
     * @var string
     */
    protected static $projectsModel = 'PaloAltoNetworks\Sentinel\Projects\Project';

    /**
     * The Eloquent device model name.
     *
     * @var string
     */
    protected static $devicesModel = 'PaloAltoNetworks\Sentinel\Devices\Device';

    /**
     * The Eloquent project model name.
     *
     * @var string
     */
    protected static $keysModel = 'PaloAltoNetworks\Sentinel\ApiKeys\ApiKey';
    protected static $logsModel = 'PaloAltoNetworks\Sentinel\ApiKeys\FWLog';


    protected static $projectDeviceRelationModel = 'PaloAltoNetworks\Sentinel\ProjectDevice\ProjectDeviceRelation';
    /**
     * The Users relationship.
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsToMany
     */
    public function projects()
    {
        return $this->belongsToMany(static::$projectsModel, 'project_devices', 'device_id', 'project_name')->withTimestamps();
    }
//    public function roles()  //In EloquentUser class
//    {
//        return $this->belongsToMany(static::$rolesModel, 'role_users', 'user_id', 'role_id')->withTimestamps();
//    }

    /**
     * {@inheritDoc}
     */
    public static function getDeviceModel()
    {
        return static::$devicesModel;
    }
    
    public function api_keys()
    {
        return $this->hasMany(static::$keysModel, 'device_id');
    }

    public function getApiKeys()
    {
        return $this->api_keys;
    }

    /**
     * {@inheritDoc}
     */
    public function delete()
    {
        if ($this->exists) {
            $this->api_keys()->delete();
            $this->deleteLicenses();
        }

        parent::delete();
    }


    public function getSelectedBy(){
        return $this->hasMany(static::$projectDeviceRelationModel, 'device_id');
    }

    public function deleteLicenses(){
        require_once INC_ROOT.'/libs/database.php';
        $query = "DELETE FROM licenses WHERE serial='$this->serial'";
        $pandbRBAC = selectDatabase('pandbRBAC');
        $pandbRBAC->query($query);
    }

    public function myPanorama()
    {
        return $this->belongsTo(static::$devicesModel, 'management','serial');
    }

    public function getCSV_Path():string{
        if($this->csv_path == '') {
            if($myPanorama = $this->myPanorama()->getResults()) {
                return $myPanorama->csv_path;
            }
        }

        return $this->csv_path;
    }

    public function isSyslog():bool {
        return $this->avoidToday();
    }

    public function avoidToday():bool {
        return $this->avoidToday;
    }
}