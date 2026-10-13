<?php
/**
 * Created by PhpStorm.
 * User: didacgil
 * Date: 8/3/16
 * Time: 13:59
 */
namespace PaloAltoNetworks\Validation;

use Cartalyst\Sentinel\Native\Facades\Sentinel;
use PaloAltoNetworks\Helpers\Hash;
use Violin\Violin;
use PaloAltoNetworks\Sentinel\User\User;


class UserValidator extends Violin
{
    protected $user;
    protected $hash;
    protected $auth;

    public function __construct(USER $user, Hash $hash, $auth = null)
    {
        $this->user = $user;
        $this->hash = $hash;
        $this->auth = $auth;

        $this->addFieldMessages([
            'email' => [
                'uniqueEmail' => '<br>This <b>Account Name</b> is already taken',
                'xssSave'        => 'This is not a valid email'
            ],
            'username' => [
                'uniqueUsername' => '<br>This <b>Username</b> is already taken',
                'xssSave'        => 'This is not a valid name'
            ],
            'role' => [
                'roleExists' => '<br>This <b>Role</b> does not exist',
                'required'  => '<br>Select a user\'s <b>Role</b>'
            ],
            'location' => [
                'locationExists' => '<br>The <b>Authentication Server</b> is not valid',
                'required'  => '<br>Select an <b>Authentication Server</b>'
            ],
            'last_name' => [
                'required'  => '<br>Enter the <b>Last Name</b>',
                'xssSave'        => 'This is not a valid last name'

            ],
            'first_name' => [
                'required'  => '<br>Enter the <b>First Name</b>',
                'xssSave'        => 'This is not a valid name'

            ],
            'timezone' => [
                'required'  => '<br>Define a <b>Timezone</b>',
                'xssSave'        => 'This is not a valid name'

            ],
            'password' => [
                'min'    => '<br>The <b>Password Complexity</b> is too weak',
                'required'  => '<br>Enter the user\'s <b>Password</b>'
            ],
            'password_confirm' => [
                'matches' => '<br><b>Passwords</b> do not match',
                'required'  => '<br>Enter the <b>Confirmation Password</b>'

            ],

        ]);

        $this->addRuleMessages([
                 'matchesCurrentPassword' => 'You have not entered the correct current password.'
        ]);
    }

    public function validate_uniqueEmail($value, $input, $args)
    {
        $id = $args[0];
        $user = $this->user->where('email', $value)->where('id',"!=",$id);

//          $user = $this->user->where('email', $value); //Looks for a user in the table used in the Model User and returns it if found
//        return ! (bool) $user->count();
        return ($user->count()== 0) ? true: false;
    }


    public function validate_matchesCurrentPassword($value, $input, $args)
    {
        $credentials = [
            'email' => $this->auth->email,
            'password' => $value
        ];
        return (bool) Sentinel::authenticate($credentials);
    }

    public function validate_roleExists($value, $input, $args)
    {
        $role = Sentinel::findRoleBySlug($value);
        if (isset($role)) return true;
        return false;
    }

    public function validate_locationExists($value, $input, $args)
    {
        global $app;
        if(!isset($value)){
            return false;
        }
        $typeandServer= explode(".", $value);
        if($typeandServer[0] == 'local'){
            return true;
        }
        elseif($typeandServer[0]=='ldap'){
            if(isset($typeandServer[1])) {
                if($server = $app->ldapserver->where("id", $typeandServer[1])->get()->first()){
                    return true;
                }
            }
        }
        elseif($typeandServer[0]=='radius'){
            if(isset($typeandServer[1])) {
                if($server = $app->radiusserver->where("id", $typeandServer[1])->get()->first()){
                    return true;
                }
            }
        }

        return false;
    }

    public function validate_xssSave($value, $input, $args){
        if($value != htmlspecialchars($value, ENT_QUOTES, 'UTF-8')){
            return false;
        }
        return true;
    }
}