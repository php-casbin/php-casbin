<?php

declare(strict_types=1);

namespace Casbin\Rbac\DefaultRoleManager;
use Closure;

/**
 * Role.
 * Represents the data structure for a role in RBAC.
 *
 * @author techlee@qq.com
 */
class Role
{
    /**
     * @var string
     */
    public $name = '';

    /**
     * @var Role[]
     */
    private $roles = [];

    /**
     * Role constructor.
     *
     * @param string $name
     */
    public function __construct(string $name)
    {
        $this->name = $name;
    }

    /**
     * @param self $role
     */
    public function addRole(self $role): void
    {
        // determine whether this role has been added
        foreach ($this->roles as $rr) {
            if ($rr->name == $role->name) {
                return;
            }
        }
        $this->roles[] = $role;
    }

    /**
     * @param self $role
     */
    public function deleteRole(self $role): void
    {
        foreach ($this->roles as $key => $rr) {
            if ($rr->name == $role->name) {
                unset($this->roles[$key]);

                return;
            }
        }
    }

    /**
     * @param string $name
     * @param int $hierarchyLevel
     *
     * @return bool
     */
    public function hasRole(string $name, int $hierarchyLevel): bool
    {
        if ($this->hasDirectRole($name)) {
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

    /**
     * @param string   $name
     * @param int      $hierarchyLevel
     * @param Closure  $matchingFunc
     *
     * @return bool
     */
    public function hasRoleWithMatchingFunc(string $name, int $hierarchyLevel, Closure $matchingFunc): bool
    {
        if ($this->hasDirectRoleWithMatchingFunc($name, $matchingFunc)) {
            return true;
        }

        if ($hierarchyLevel <= 0) {
            return false;
        }

        foreach ($this->roles as $role) {
            if ($role->hasRoleWithMatchingFunc($name, $hierarchyLevel - 1, $matchingFunc)) {
                return true;
            }
        }
        return false;
    }

    /**
     * @param string $name
     *
     * @return bool
     */
    public function hasDirectRole(string $name): bool
    {
        foreach ($this->roles as $role) {
            if ($role->name == $name) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param string   $name
     * @param Closure  $matchingFunc
     *
     * @return bool
     */
    public function hasDirectRoleWithMatchingFunc(string $name, Closure $matchingFunc): bool
    {
        foreach ($this->roles as $role) {
            if ($role->name == $name || $matchingFunc($name, $role->name)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return string
     */
    public function toString(): string
    {
        $len = \count($this->roles);

        if (0 == $len) {
            return '';
        }

        $names = implode(', ', $this->getRoles());

        if (1 == $len) {
            return $this->name . ' < ' . $names;
        } else {
            return $this->name . ' < (' . $names . ')';
        }
    }

    /**
     * @return string[]
     */
    public function getRoles(): array
    {
        return array_map(function (Role $role) {
            return $role->name;
        }, $this->roles);
    }
}
