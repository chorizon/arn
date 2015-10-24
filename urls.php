<?php

use PhangoApp\PhaRouter\Routes;

//Routes::$urls['welcome\/([0-9]+)\/(\w+)']=array('index', 'page');

Routes::$urls['arn\/([^\/]*)$']=array('index', 'home');

Routes::$urls['arn\/check_process\/([^\/]*)\/([^\/]*)$']=array('index', 'check_process');

?>