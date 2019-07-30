<?php

namespace Casbin\Rbac\DefaultRoleManager;

use Casbin\Exceptions\CasbinException;
use Casbin\Rbac\Role;
use Casbin\Rbac\RoleManager as RoleManagerContract;
use Casbin\Log\Log;

/**
 * Class RoleManager.
 * provides a default implementation for the RoleManager interface.
 *
 * @author techlee@qq.com
 */
class RoleManager implements RoleManagerContract
{
    /**
     * @var array
     */
    protected $allRoles;

    /**
     * @var int
     */
    protected $maxHierarchyLevel;

    /**
     * RoleManager constructor.
     *
     * @param $maxHierarchyLevel
     */
    public function __construct($maxHierarchyLevel)
    {
        $this->allRoles = [];
        $this->maxHierarchyLevel = $maxHierarchyLevel;
    }

    /**
     * @param string $name
     *
     * @return bool
     */
    protected function hasRole($name)
    {
        return isset($this->allRoles[$name]);
    }

    /**
     * @param string $name
     *
     * @return mixed
     */
    protected function createRole($name)
    {
        if (!isset($this->allRoles[$name])) {
            $this->allRoles[$name] = new Role($name);
        }

        return $this->allRoles[$name];
    }

    /**
     * clears all stored data and resets the role manager to the initial state.
     */
    public function clear()
    {
        $this->allRoles = [];
    }

    /**
     * adds the inheritance link between role: name1 and role: name2.
     * aka role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     *
     * @param string $name1
     * @param string $name2
     * @param string $domain
     */
    public function addLink($name1, $name2, $domain = '')
    {
        if ('' != $domain) {
            $name1 = $domain.'::'.$name1;
            $name2 = $domain.'::'.$name2;
        }

        $role1 = $this->createRole($name1);
        $role2 = $this->createRole($name2);
        $role1->addRole($role2);
    }

    /**
     * deletes the inheritance link between role: name1 and role: name2.
     * aka role: name1 does not inherit role: name2 any more.
     * domain is a prefix to the roles.
     *
     * @param string $name1
     * @param string $name2
     * @param string $domain
     */
    public function deleteLink($name1, $name2, $domain = '')
    {
        if ('' != $domain) {
            $name1 = $domain.'::'.$name1;
            $name2 = $domain.'::'.$name2;
        }

        if (!$this->hasRole($name1) || !$this->hasRole($name2)) {
            throw new CasbinException('error: name1 or name2 does not exist');
        }

        $role1 = $this->createRole($name1);
        $role2 = $this->createRole($name2);
        $role1->deleteRole($role2);
    }

    /**
     * determines whether role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     *
     * @param string $name1
     * @param string $name2
     * @param string $domain
     *
     * @return bool
     */
    public function hasLink($name1, $name2, $domain = '')
    {
        if ('' != $domain) {
            $name1 = $domain.'::'.$name1;
            $name2 = $domain.'::'.$name2;
        }

        if ($name1 == $name2) {
            return true;
        }

        if (!$this->hasRole($name1) || !$this->hasRole($name2)) {
            return false;
        }

        $role1 = $this->createRole($name1);

        return $role1->hasRole($name2, $this->maxHierarchyLevel);
    }

    /**
     * gets the roles that a subject inherits.
     * domain is a prefix to the roles.
     *
     * @param string $name
     * @param string $domain
     *
     * @return array
     */
    public function getRoles($name, $domain = '')
    {
        if ('' != $domain) {
            $name = $domain.'::'.$name;
        }

        if (!$this->hasRole($name)) {
            return [];
        }

        $roles = $this->createRole($name)->getRoles();
        if ('' != $domain) {
            foreach ($roles as $key => $value) {
                $roles[$key] = \substr($roles[$key], \strlen($domain) + 2);
            }
        }

        return $roles;
    }

    /**
     * gets the users that inherits a subject.
     * domain is an unreferenced parameter here, may be used in other implementations.
     *
     * @param string $name
     * @param string $domain
     *
     * @return array
     */
    public function getUsers($name, $domain = '')
    {
        if ('' != $domain) {
            $name = $domain.'::'.$name;
        }

        if (!$this->hasRole($name)) {
            // throw new CasbinException('error: name does not exist');
            return [];
        }

        $names = [];
        array_map(function ($role) use (&$names, $name, $domain) {
            if ($role->hasDirectRole($name)) {
                $names[] = '' != $domain ? \substr($role->name, \strlen($domain) + 2) : $role->name;
            }
        }, $this->allRoles);

        return $names;
    }

    /**
     * prints all the roles to log.
     */
    public function printRoles()
    {
        $line = [];
        array_map(function ($role) use (&$line) {
            if ($text = $role->toString()) {
                $line[] = $text;
            }
        }, $this->allRoles);
        Log::logPrint(implode(', ', $line));
    }
}
