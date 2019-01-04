<?php

namespace Casbin\Rbac\DefaultRoleManager;

use Casbin\Exceptions\CasbinException;
use Casbin\Rbac\Role;
use Casbin\Rbac\RoleManager as RoleManagerContract;
use Casbin\Log\Log;

/**
 * RoleManager.
 *
 * @author techlee@qq.com
 */
class RoleManager implements RoleManagerContract
{
    protected $allRoles;

    protected $maxHierarchyLevel;

    public function __construct($maxHierarchyLevel)
    {
        $this->allRoles = [];
        $this->maxHierarchyLevel = $maxHierarchyLevel;
    }

    protected function hasRole($name)
    {
        return isset($this->allRoles[$name]);
    }

    protected function createRole($name)
    {
        if (!isset($this->allRoles[$name])) {
            $this->allRoles[$name] = new Role($name);
        }

        return $this->allRoles[$name];
    }

    public function clear()
    {
        $this->allRoles = [];
    }

    public function addLink($name1, $name2, ...$domain)
    {
        if (1 == \count($domain)) {
            $name1 = $domain[0].'::'.$name1;
            $name2 = $domain[0].'::'.$name2;
        } elseif (\count($domain) > 1) {
            throw new CasbinException('error: domain should be 1 parameter');
        }

        $role1 = $this->createRole($name1);
        $role2 = $this->createRole($name2);
        $role1->addRole($role2);
    }

    public function deleteLink($name1, $name2, ...$domain)
    {
        if (1 == \count($domain)) {
            $name1 = $domain[0].'::'.$name1;
            $name2 = $domain[0].'::'.$name2;
        } elseif (\count($domain) > 1) {
            throw new CasbinException('error: domain should be 1 parameter');
        }

        if (!$this->hasRole($name1) || !$this->hasRole($name2)) {
            throw new CasbinException('error: name1 or name2 does not exist');
        }

        $role1 = $this->createRole($name1);
        $role2 = $this->createRole($name2);
        $role1->deleteRole($role2);
    }

    public function hasLink($name1, $name2, ...$domain)
    {
        if (1 == \count($domain)) {
            $name1 = $domain[0].'::'.$name1;
            $name2 = $domain[0].'::'.$name2;
        } elseif (\count($domain) > 1) {
            throw new CasbinException('error: domain should be 1 parameter');
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

    public function getRoles($name, ...$domain)
    {
        if (1 == \count($domain)) {
            $name = $domain[0].'::'.$name;
        } elseif (\count($domain) > 1) {
            throw new CasbinException('error: domain should be 1 parameter');
        }

        if (!$this->hasRole($name)) {
            return [];
        }

        $roles = $this->createRole($name)->getRoles();
        if (1 == \count($domain)) {
            foreach ($roles as $key => $value) {
                $roles[$key] = \array_slice($roles[$key], \strlen($domain[0]) + 2);
            }
        }

        return $roles;
    }

    public function getUsers($name, ...$domain)
    {
        if (!$this->hasRole($name)) {
            throw new CasbinException('error: name does not exist');
        }

        $names = [];
        array_map(function ($role) use (&$names, $name) {
            if ($role->hasDirectRole($name)) {
                $names[] = $role->name;
            }
        }, $this->allRoles);

        return $names;
    }

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
