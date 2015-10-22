<?php

use PhangoApp\PhaRouter\Controller;
use PhangoApp\PhaUtils\Utils;
use Chorizon\Arn\Config;

ini_set('html_errors', false);

define('ERROR_IP', 1);

define('ERROR_ARGUMENTS', 2);

define('ERROR_SECRET_KEY', 3);

class indexController extends Controller {

    public function home($secret_key='')
    {
        
        //['category' => 'mail', 'module' => 'mail_unix', 'script' => 'add_domain']
        
        settype($_GET['task_id'], 'integer');
        settype($_GET['ip'], 'string');
        
        $arr_result=array('task_id' => $_GET['task_id'], 'MESSAGE' => "Begin process via ssh...", 'ERROR' => 0, 'CODE_ERROR' => 0, 'PROGRESS' => 0);
        
        $send_process=1;
        
        if(!filter_var($_GET['ip'],  FILTER_VALIDATE_IP))
        {
        
            $send_process=0;
        
            $arr_result=array('task_id' => $_GET['task_id'], 'MESSAGE' => "Error, IP ".Utils::form_text($_GET['ip'])." invalid", 'ERROR' => 1, 'CODE_ERROR' => ERROR_IP, 'PROGRESS' => 100);
        
        }
        
        $ip=$_GET['ip'];
        
        settype($_GET['ssh_port'], 'integer');
        
        if($_GET['ssh_port']==0)
        {
        
            $_GET['ssh_port']=22;
        
        }
        
        settype($_GET['category'], 'string');
        settype($_GET['module'], 'string');
        settype($_GET['script'], 'string');
        
        $_GET['category']=basename(Utils::form_text($_GET['category']));
        $_GET['module']=basename(Utils::form_text($_GET['module']));
        $_GET['script']=basename(Utils::form_text($_GET['script']));
        
        if($_GET['category']=='' || $_GET['module']=='' || $_GET['script']=='')
        {
        
            $send_process=0;
        
            $arr_result=array('task_id' => $_GET['task_id'], 'MESSAGE' => "Error, invalid request, you need valid category, module and script fields", 'ERROR' => 1, 'CODE_ERROR' => ERROR_ARGUMENTS, 'PROGRESS' => 100);
        
        }
        
        $final_secret_key=hash('sha512', $secret_key.'+'.SECRET_KEY_PASTAFARI_SERVER);
        
        if($final_secret_key===SECRET_KEY_HASHED_WITH_PASS)
        {
           
        
            if($send_process===1)
            {
            
                //Basic config
                
                Config::$settings['private_key']='';
                
                Config::$settings['password']='';
                
                Config::$settings['user_ssh']='';
            
                //Make connection ssh
                Utils::load_config('config_arn');
                
                $file_key=Config::$settings['private_key'];
                
                //Prepare ssh key
                
                $key = new \phpseclib\Crypt\RSA();
                
                try {
                    
                    $yes_password=1;
                    
                    $key->setPassword(Config::$settings['password']);
                    
                    if(file_exists($file_key))
                    {
                        
                        if(!($file_key=file_get_contents(Config::$settings['private_key'])))
                        {
                            
                            $yes_password=0;
                            
                            $arr_result=array('task_id' => $_GET['task_id'], 'MESSAGE' => "Error in authentication...", 'ERROR' => 1, 'CODE_ERROR' => ERROR_SECRET_KEY, 'PROGRESS' => 100);
                        
                        }
                        elseif(!$key->loadKey($file_key))
                        {
                        
                            $yes_password=0;
                        
                            $arr_result=array('task_id' => $_GET['task_id'], 'MESSAGE' => "Error in authentication password...", 'ERROR' => 1, 'CODE_ERROR' => ERROR_SECRET_KEY, 'PROGRESS' => 100);
                            
                        }
                    
                    }
                    else
                    {
                    
                        $yes_password=0;
                        
                        $arr_result=array('task_id' => $_GET['task_id'], 'MESSAGE' => "Error in authentication...", 'ERROR' => 1, 'CODE_ERROR' => ERROR_SECRET_KEY, 'PROGRESS' => 100);
                    
                    }
                    
                    //Declare ssh
                    
                    $ssh = new \phpseclib\Net\SSH2($ip);
                    
                    ob_start();
                    
                    if (!$ssh->login(Config::$settings['user_ssh'], $key)) {
                    
                        $error=ob_get_contents();
    
                        $arr_result=array('task_id' => $_GET['task_id'], 'MESSAGE' => "Error login in server...:".$error, 'ERROR' => 1, 'CODE_ERROR' => ERROR_SECRET_KEY, 'PROGRESS' => 100);
                    
                        $yes_password=0;
                    }
                    
                    ob_end_clean();
                    
                    $command='python3 virus/load_script.py --category '.$_GET['category'].' --module '.$_GET['module'].' --script '.$_GET['script'];
                    
                    if($yes_password===1)
                    {
                    
                        if(!$ssh->exec($command, 'packet_handler'))
                        {
                        
                            $arr_result=array('task_id' => $_GET['task_id'], 'MESSAGE' => "Error executing command...", 'ERROR' => 1, 'CODE_ERROR' => ERROR_SECRET_KEY, 'PROGRESS' => 100);
                        
                        }
                    
                    }
                
                }
                catch(Exception $e) {
                    
                    $arr_result=array('task_id' => $_GET['task_id'], 'MESSAGE' => "Error in authentication...", 'ERROR' => 1, 'CODE_ERROR' => ERROR_SECRET_KEY, 'PROGRESS' => 100);
            
                }
            }
            
        }
        else
        {
        
            $send_process=0;
        
            $arr_result=array('task_id' => $_GET['task_id'], 'MESSAGE' => "Hash is wrong...", 'ERROR' => 1, 'CODE_ERROR' => ERROR_SECRET_KEY, 'PROGRESS' => 100);
        
        }
        
        header('Content-type: text/plain');
        
        echo json_encode($arr_result);
        
        die;
    
    }

}

function packet_handler($str)
{
    
    echo $str."\n";
    
    
}

?>