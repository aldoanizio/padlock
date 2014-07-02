<?php

/**
 * @copyright  Aldo Anizio Lugão Camacho
 * @license    http://www.makoframework.com/license
 */

namespace padlock;

use \padlock\user\UserInterface;

use \mako\http\Request;
use \mako\http\Response;
use \mako\session\Session;

/**
 * Padlock authentication.
 *
 * @author  Aldo Anizio Lugão Camacho
 */

class Padlock
{
    /**
     * Have we checked for a valid login?
     *
     * @var boolean
     */

    protected $isChecked = false;

    /**
     * Status code for banned users.
     *
     * @var int
     */

    const LOGIN_BANNED = 100;

    /**
     * Status code for users who need to activate their account.
     *
     * @var int
     */

    const LOGIN_ACTIVATING = 101;

    /**
     * Status code for users who fail to provide the correct credentials.
     *
     * @var int
     */

    const LOGIN_INCORRECT = 102;

    /**
     * Request instance.
     *
     * @var \mako\http\Request
     */

    protected $request;

    /**
     * Response instance.
     *
     * @var \mako\http\Response
     */

    protected $response;

    /**
     * Session instance.
     *
     * @var \mako\session\Session
     */

    protected $session;

    /**
     * Auth key.
     *
     * @var string
     */

    protected $authKey = 'padlock_auth_key';

    /**
     * User model class.
     *
     * @var string
     */

    protected $userModel = '\padlock\user\User';

    /**
     * Cookie options.
     *
     * @var array
     */

    protected $cookieOptions =
    [
        'path'     => '/',
        'domain'   => '',
        'secure'   => false,
        'httponly' => false,
    ];

    /**
     * User instance.
     *
     * @var padlock\user\User
     */

    protected $user;

    /**
     * Constructor.
     *
     * @access  public
     * @param   \mako\http\Request     $request   Request instance
     * @param   \mako\http\Response    $response  Response instance
     * @param   \mako\session\Session  $session   Session instance
     */

    public function __construct(Request $request, Response $response, Session $session)
    {
        $this->request  = $request;
        $this->response = $response;
        $this->session  = $session;
    }

    /**
     * Sets the auth key.
     *
     * @access  public
     * @param   string  $authKey  Auth key
     */

    public function setAuthKey($authKey)
    {
        if($this->isChecked)
        {
            throw new \LogicException(vsprintf("%s(): Unable to alter auth key after login check.", [__METHOD__]));
        }

        $this->authKey = $authKey;
    }

    /**
     * Sets the user model.
     *
     * @access  public
     * @param   string  $userModel  User model
     */

    public function setUserModel($userModel)
    {
        if($this->isChecked)
        {
            throw new \LogicException(vsprintf("%s(): Unable to alter user model after login check.", [__METHOD__]));
        }

        $this->userModel = $userModel;
    }

    /**
     * Sets cookie options.
     *
     * @access  public
     * @param   array   $cookieOptions  Cookie options
     */

    public function setCookieOptions(array $cookieOptions)
    {
        if($this->isChecked)
        {
            throw new \LogicException(vsprintf("%s(): Unable to alter cookie options after login check.", [__METHOD__]));
        }

        $this->cookieOptions = $cookieOptions;
    }

    /**
     * Activates a user based on the provided auth token.
     *
     * @access  public
     * @param   string   $token  Auth token
     * @return  boolean
     */

    public function activateUser($token)
    {
        $model = $this->userModel;

        $user = $model::where('token', '=', $token)->where('activated', '=', 0)->first();

        if(!$user)
        {
            return false;
        }
        else
        {
            $user->activate();

            $user->generateToken();

            $user->save();

            return true;
        }
    }

    /**
     * Checks if a user is logged in.
     *
     * @access  protected
     * @return  \padlock\models\User|null
     */

    protected function check()
    {
        if(empty($this->user))
        {
            // Check if there'a user that can be logged in

            $token = $this->session->get($this->authKey, false);

            if($token === false)
            {
                $token = $this->request->signedCookie($this->authKey, false);

                if($token !== false)
                {
                    $this->session->put($this->authKey, $token);
                }
            }

            if($token !== false)
            {
                $model = $this->userModel;

                $this->user = $model::where('token', '=', $token)->first();

                if($this->user === false || $this->user->isBanned() || !$this->user->isActivated())
                {
                    $this->logout();
                }
            }

            // Set checked status to TRUE

            $this->isChecked = true;
        }

        return $this->user;
    }

    /**
     * Returns FALSE if the user is logged in and TRUE if not.
     *
     * @access  public
     * @return  boolean
     */

    public function isGuest()
    {
        return $this->check() === null;
    }

    /**
     * Returns FALSE if the user isn't logged in and TRUE if it is.
     *
     * @access  public
     * @return  boolean
     */

    public function isLoggedIn()
    {
        return $this->check() !== null;
    }

    /**
     * Returns the authenticated user or NULL if no user is logged in.
     *
     * @access  public
     * @return  null|padlock\user\User
     */

    public function user()
    {
        return $this->check();
    }

    /**
     * Returns TRUE if the email + password combination matches and the user is activated and not banned.
     * A status code (LOGIN_ACTIVATING, LOGIN_BANNED or LOGIN_INCORRECT) will be retured in all other situations.
     *
     * @access  protected
     * @param   string       $email     User email
     * @param   string       $password  User password
     * @param   boolean      $force     (optional) Skip the password check?
     * @param   boolean      $callback  (optional) Set additional query parameters
     * @return  boolean|int
     */

    protected function authenticate($email, $password, $force = false, $callback = false)
    {
        $model = $this->userModel;

        // Start query

        $query = $model::where('email', '=', $email);

        // Call user query builder

        if($callback !== false)
        {
            $this->userQueryBuilder($callback, $query);
        }

        // Finish query

        $user = $query->first();

        // Check user

        if($user !== false && ($user->validatePassword($password) || $force))
        {
            if(!$user->isActivated())
            {
                return static::LOGIN_ACTIVATING;
            }

            if($user->isBanned())
            {
                return static::LOGIN_BANNED;
            }

            $this->user = $user;

            return true;
        }

        return static::LOGIN_INCORRECT;
    }

    /**
     * Logs in a user with a valid email/password combination.
     * Returns TRUE if the email + password combination matches and the user is activated and not banned.
     * A status code (LOGIN_ACTIVATING, LOGIN_BANNED or LOGIN_INCORRECT) will be retured in all other situations.
     *
     * @access  public
     * @param   string       $email     User email
     * @param   string       $password  User password
     * @param   boolean      $remember  (optional) Set a remember me cookie?
     * @param   boolean      $force     (optional) Login the user without checking the password?
     * @param   boolean      $callback  (optional) Set additional query parameters
     * @return  boolean|int
     */

    public function login($email, $password, $remember = false, $force = false, $callback = false)
    {
        $authenticated = $this->authenticate($email, $password, $force, $callback);

        if($authenticated === true)
        {
            $this->session->regenerateId();

            $this->session->put($this->authKey, $this->user->getToken());

            if($remember === true)
            {
                $this->response->signedCookie($this->authKey, $this->user->getToken(), (3600 * 24 * 365), $this->cookieOptions);
            }

            return true;
        }

        return $authenticated;
    }

    /**
     * Build login query using closures
     *
     * @access  protected
     * @param   mixed             $callback
     * @param   \padlock\Padlock  $query
     * @return  mixed
     */

    protected function userQueryBuilder($callback, $query)
    {
        if($callback instanceof \Closure)
        {
            return call_user_func($callback, $query);
        }

        throw new \InvalidArgumentException('Callback is not valid.');
    }

    /**
     * Login a user without checking the password.
     *
     * @access  public
     * @param   mixed    $identifier  User email or id
     * @param   boolean  $remember    (optional) Set a remember me cookie?
     * @return  boolean
     */

    public function forceLogin($email, $remember = false)
    {
        return ($this->login($email, null, $remember, true) === true);
    }

    /**
     * Logs the user out.
     *
     * @access  public
     */

    public function logout()
    {
        $this->session->regenerateId();

        $this->session->remove($this->authKey);

        $this->response->deleteCookie($this->authKey, $this->cookieOptions);

        $this->user = null;
    }
}