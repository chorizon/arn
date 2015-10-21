<?php

use PhangoApp\PhaRouter\Routes;

//Routes::$urls['welcome\/([0-9]+)\/(\w+)']=array('index', 'page');

Routes::$urls['pastafari\/([^\/]*)$']=array('index', 'home');

?>