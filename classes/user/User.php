<?php

/**
 * @copyright  Aldo Anizio Lugão Camacho
 * @license    http://www.makoframework.com/license
 */

namespace padlock\user;

use \mako\security\Password;

/**
 * Padlock user model.
 *
 * @author  Aldo Anizio Lugão Camacho
 */

class User extends \mako\database\midgard\ORM
{
    //---------------------------------------------
    // Class traits
    //---------------------------------------------

    use \padlock\user\UserTrait;

    //---------------------------------------------
    // Class properties
    //---------------------------------------------

    /**
     * Table name.
     *
     * @var string
     */

    protected $tableName = 'users';

    //---------------------------------------------
    // Mutators and Accessors
    //---------------------------------------------

    /**
     * Password mutator.
     *
     * @access  public
     * @return  string
     */

    public function passwordMutator($password)
    {
        return Password::hash($password);
    }
}