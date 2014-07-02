<?php

/**
 * @copyright  Aldo Anizio Lugão Camacho
 * @license    http://www.makoframework.com/license
 */

namespace padlock\service;

use \padlock\Padlock;

/**
 * Padlock service.
 *
 * @author  Aldo Anizio Lugão Camacho
 */

class PadlockService extends \mako\application\services\Service
{
    /**
     * Registers the service.
     *
     * @access  public
     */

    public function register()
    {
        $this->container->registerSingleton(['padlock\Padlock', 'padlock'], function($container)
        {
            $config = $container->get('config')->get('padlock::config');

            $padlock = new Padlock($container->get('request'), $container->get('response'), $container->get('session'));

            $padlock->setAuthKey($config['auth_key']);

            $padlock->setUserModel($config['user_model']);

            $padlock->setCookieOptions($config['cookie_options']);

            return $padlock;
        });
    }
}