<?php

namespace Casbin\Rbac;

/**
 * Role.
 *
 * @author techlee@qq.com
 */
class Role
{
    public $name = '';

    private $roles = [];

    public function __construct($name)
    {
        $this->name = $name;
    }

    public function addRole(self $role)
    {
        foreach ($this->roles as $rr) {
            if ($rr->name == $role->name) {
                return;
            }
        }
        $this->roles[] = $role;
    }

    public function deleteRole(self $role)
    {
        foreach ($this->roles as $key => $rr) {
            if ($rr->name == $role->name) {
                unset($this->roles[$key]);

                return;
            }
        }
    }

    public function hasRole($name, $hierarchyLevel)
    {
        if ($name == $this->name) {
            return true;
        }
        if ($hierarchyLevel <= 0) {
            return false;
        }

        foreach ($this->roles as $role) {
            if ($role->hasRole($name, $hierarchyLevel - 1)) {
                return true;
            }
        }

        return false;
    }

    public function hasDirectRole($name)
    {
        foreach ($this->roles as $role) {
            if ($role->name == $name) {
                return true;
            }
        }

        return false;
    }

    public function toString()
    {
        if (0 == \count($this->roles)) {
            return '';
        }

        $names = implode(', ', $this->getRoles());

        if (1 == \count($this->roles)) {
            return $this->name.' < '.$names;
        } else {
            return $this->name.' < ('.$names.')';
        }
    }

    public function getRoles()
    {
        return array_map(function ($role) {
            return $role->name;
        }, $this->roles);
    }
}
