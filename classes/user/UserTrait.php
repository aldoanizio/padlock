<?php

/**
 * @copyright  Aldo Anizio Lugão Camacho
 * @license    http://www.makoframework.com/license
 */

namespace padlock\user;


use \mako\security\Password;
use \mako\utility\UUID;


/**
 * UserTrait.
 *
 * @author  Aldo Anizio Lugão Camacho
 */

trait UserTrait
{
    /**
     * Returns the user id.
     *
     * @access  public
     * @return  int|string
     */

    public function getId()
    {
        $this->getPrimaryKeyValue();
    }

    /**
     * Sets the user email address.
     *
     * @access  public
     * @param   string  $email  Email address
     */

    public function setEmail($email)
    {
        $this->email = $email;
    }

    /**
     * Returns the user email address.
     *
     * @access  public
     * @return  string
     */

    public function getEmail()
    {
        return $this->email;
    }

    /**
     * Sets the user password.
     *
     * @access  public
     * @param   string  $password  Password
     */

    public function setPassword($password)
    {
        $this->password = $password;
    }

    /**
     * Returns the user password.
     *
     * @access  public
     * @return  string
     */

    public function getPassword()
    {
        return $this->password;
    }

    /**
     * Generates a new access token.
     *
     * @access  public
     */

    public function generateToken()
    {
        if(!$this->exists)
        {
            throw new \LogicException(vsprintf("%s(): You can only generate auth tokens for users that exist in the database.", [__METHOD__]));
        }

        $this->token = hash('sha256', UUID::v4() . $this->getId() . uniqid('token', true));
    }

    /**
     * Returns the user access token.
     *
     * @access  public
     * @return  string
     */

    public function getToken()
    {
        return $this->token;
    }

    /**
     * Activates the user.
     *
     * @access  public
     */

    public function activate()
    {
        $this->activated = 1;
    }

    /**
     * Deactivates the user.
     *
     * @access  public
     */

    public function deactivate()
    {
        $this->activated = 0;
    }

    /**
     * Returns TRUE of the user is activated and FALSE if not.
     *
     * @access  public
     * @return  boolean
     */

    public function isActivated()
    {
        return $this->activated == 1;
    }

    /**
     * Bans the user.
     *
     * @access  public
     */

    public function ban()
    {
        $this->banned = 1;
    }

    /**
     * Unbans the user.
     *
     * @access  public
     */

    public function unban()
    {
        $this->banned = 0;
    }

    /**
     * Returns TRUE if the user is banned and FALSE if not.
     *
     * @return  boolean
     */

    public function isBanned()
    {
        $this->banned == 1;
    }

    /**
     * Validates a user password.
     *
     * @access  public
     * @param   string   $password  Password
     * @return  boolean
     */

    public function validatePassword($password)
    {
        return Password::validate($password, $this->password);
    }
}