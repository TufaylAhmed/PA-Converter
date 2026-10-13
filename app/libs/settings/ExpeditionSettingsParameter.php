<?php

require_once INC_ROOT.'/libs/common/MemoryObjects/Response.php';
use \PaloAltoNetworks\Expedition\MemoryObjects\Response;

class ExpeditionSettingsParameter implements \JsonSerializable
{
    /* @var String $name*/
    private $name;
    /* @var String $type*/
    private $type;

    /* @var String $icon*/
    private $icon;

    /* @var string $description*/
    private $description;

    /* @var bool $modifyable */
    private $modifiable;

    private $value;
    private $defaultValue;

    static function getDefaults(){
        return [
            'DBServer' => new ExpeditionSettingsParameter('DBServer', 'Server hosting Expedition databases','Database','fa-database', false,'localhost', ''),
            'DBUser'=> new ExpeditionSettingsParameter('DBUser', 'User for querying Expedition databases','Database','fa-database',false,'root', ''),
            'DBPass'=>new ExpeditionSettingsParameter('DBPass', 'Password for queryingExpedition databases','Database','fa-database',false,'paloalto', ''),
            'DBName' => new ExpeditionSettingsParameter('DBName', 'Default database schema for projects','Database','fa-database',false,'project_schema', ''),
            'DBSQL_LOG_BIN'=>new ExpeditionSettingsParameter('DBSQL_LOG_BIN', 'Enable of Disable SQL logging. This is independent from Expedition logging features','Database','fa-database',true, '0', ''),
            'GLOBAL_connect_timeout'=>new ExpeditionSettingsParameter('GLOBAL_connect_timeout', 'Maximum time to establish connection with MySQL server (in seconds).','Database','fa-database',true, '10', ''),
            'GLOBAL_wait_timeout'=>new ExpeditionSettingsParameter('GLOBAL_wait_timeout', 'Time server waits for activity on a connection before closing (in seconds).','Database','fa-database',true, '28800', ''),
            'GLOBAL_interactive_timeout'=>new ExpeditionSettingsParameter('GLOBAL_interactive_timeout', 'Time server waits for activity on on interactive connection before closing (in seconds).','Database','fa-database',true, '28800', ''),
            'GLOBAL_max_allowed_packet'=>new ExpeditionSettingsParameter('GLOBAL_max_allowed_packet', 'Specifies maximum size of a packet or generated string.','Database','fa-database',true, '104857600', ''),
            'GLOBAL_max_connections'=>new ExpeditionSettingsParameter('GLOBAL_max_connections', 'Specifies maximum number of simultaneous client connections allowed to the server.','Database','fa-database',true, '200', ''),

            'PARSER_max_execution_time'=>new ExpeditionSettingsParameter('PARSER_max_execution_time', 'Maximum execution time for a Migration Parser script','PHP Execution', "fa-cogs",true,10000, ''),
            'PARSER_max_execution_memory'=>new ExpeditionSettingsParameter('PARSER_max_execution_memory', 'Maximum consumed Memory for a Migration Parser script. A value of -1 indicates no limit.','PHP Execution',"fa-cogs",true,'1G', ''),
            'PARSER_max_number_address_per_group'=>new ExpeditionSettingsParameter('PARSER_max_number_address_per_group', 'During a migration, set a limit for the maximum number of address objects per address group. A value of -1 indicates no limit.','PHP Execution',"fa-cogs",true,'-1', ''),

            'MAXSUPERUSERS'=>new ExpeditionSettingsParameter('MAXSUPERUSERS', 'Maximum number of defined Expedition administrators before rising a Warning message','Authentication','fa-users',true,3, ''),
            'MAX_RULES_TO_ANALYZE'=>new ExpeditionSettingsParameter('MAX_RULES_TO_ANALYZE', 'Top number of Security Rules to analyze for Dashboard reports','Project Analysis','fa-bar-chart',true, 600, ''),
            'RECOMMENDED_PANOS_VERSION'=>new ExpeditionSettingsParameter('RECOMMENDED_PANOS_VERSION', 'PANOS version recommended/default when device version is not available','PHP Execution','fa-bar-chart',true, 9.1, ''),
            'DEVICE_CONNECTION_TIMEOUT'=>new ExpeditionSettingsParameter('DEVICE_CONNECTION_TIMEOUT', 'Connection timeout in seconds used when connecting to devices (restart Task Manager - PanReadOrders - after changing the value)','PHP Execution','fa-bar-chart',true, 900, ''),
            'DEVICE_DEBUG_CONNECTION_ENABLED'=>new ExpeditionSettingsParameter('DEVICE_DEBUG_CONNECTION_ENABLED', 'Configuration enabling verbose debugging for device connections. Ensure set to false by default (1=enabled, 0=disabled).','PHP Execution','fa-bar-chart',true, 0, 0)
        ];
    }

    static function updateVariable(String $variableName, $value):Response{

        // validate data
        $to_check = $value;
        $lastChar = substr($value, -1);  // Extract the last character
        if (ctype_alpha($lastChar)) {  // Check if it is a letter
            $to_check = substr($value, 0,strlen($value)-1);
        }
        if(!is_numeric($to_check)){
            return new Response(true, 0, "$variableName NOT updated successfully. Not valid value $value");
        }

        // if the variable is not in the userSetting file (when adding new variables and user is just updating the installation)
        if(strpos(file_get_contents("/home/userSpace/userDefinitions.php"),$variableName) === false) {
            $variable_string = "define ('". $variableName . "', " . $value . ");".PHP_EOL;
            $user_settings_file = fopen('/home/userSpace/userDefinitions.php', 'a');
            fwrite($user_settings_file, $variable_string);
            fclose($user_settings_file);
            //define($variableName,$value);
        } else {
            // the variable is in the userSetting file
            $replacement = 'sed -i -E "s/(.+)' . $variableName . '(.+)/define (\'' . $variableName . '\',\'' . $value . '\');/" /home/userSpace/userDefinitions.php';
            exec($replacement);
            //define($variableName,$value);
        }
        return new Response(true, 0, "$variableName updated successfully. New value $value");
    }

    static function resetVariable():Response{
        $userDefinitionsPath = "/home/userSpace/userDefinitions.php";
        copy(INC_ROOT.'/libs/common/userDefinitions.php', $userDefinitionsPath);
        return new Response(true, 0, "userSettings has been restored to default values");
    }

    public function __construct(string $name, string $description, string $type,string $icon,  bool $modifiable, $defaultValue='',$value='')
    {
        $this->name = $name;
        $this->description = $description;
        $this->icon = $icon;
        $this->modifiable = $modifiable;
        $this->type = $type;
        $this->defaultValue = $defaultValue;
        $this->value = $value;
    }

    public function setValue($value){
        $this->value = $value;
    }

    public function getValue(){
        return $this->value;
    }

    public function getDefaultValue(){
        return $this->defaultValue;
    }

    public function getName():string{
        return $this->name;
    }

    public function getType():string{
        return $this->getType();
    }

    public function getDescription():string{
        return $this->description;
    }

    public function isModifiable():bool{
        return $this->modifiable;
    }

    public function jsonSerialize()
    {
        // TODO: Implement __toString() method.
        $vars = get_object_vars($this);

        return $vars;

    }
}