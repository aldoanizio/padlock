<?php

/**
 * @copyright  Aldo Anizio Lugão Camacho
 * @license    http://www.makoframework.com/license
 */

namespace padlock\user;

/**
 * User interface.
 *
 * @author  Aldo Anizio Lugão Camacho
 */

interface UserInterface
{
    public function getId();
    public function setEmail($email);
    public function getEmail();
    public function setPassword($password);
    public function getPassword();
    public function generateToken();
    public function getToken();
    public function activate();
    public function deactivate();
    public function isActivated();
    public function ban();
    public function unban();
    public function isBanned();
    public function save();
    public function delete();
    public function validatePassword($password);
}