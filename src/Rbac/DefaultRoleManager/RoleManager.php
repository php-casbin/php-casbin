<?php

declare(strict_types=1);

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
     * @param int $maxHierarchyLevel
     */
    public function __construct(int $maxHierarchyLevel)
    {
        $this->allRoles = [];
        $this->maxHierarchyLevel = $maxHierarchyLevel;
    }

    /**
     * @param string $name
     *
     * @return bool
     */
    protected function hasRole(string $name): bool
    {
        return isset($this->allRoles[$name]);
    }

    /**
     * @param string $name
     *
     * @return Role
     */
    protected function createRole(string $name): Role
    {
        if (!isset($this->allRoles[$name])) {
            $this->allRoles[$name] = new Role($name);
        }

        return $this->allRoles[$name];
    }

    /**
     * clears all stored data and resets the role manager to the initial state.
     */
    public function clear(): void
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
     * @param string ...$domain
     */
    public function addLink(string $name1, string $name2, string ...$domain): void
    {
        $prefix = self::getPrefix(...$domain);

        $this->createRole($prefix.$name1)->addRole(
            $this->createRole($prefix.$name2)
        );
    }

    /**
     * deletes the inheritance link between role: name1 and role: name2.
     * aka role: name1 does not inherit role: name2 any more.
     * domain is a prefix to the roles.
     *
     * @param string $name1
     * @param string $name2
     * @param string ...$domain
     */
    public function deleteLink(string $name1, string $name2, string ...$domain): void
    {
        $prefix = self::getPrefix(...$domain);

        list($name1, $name2) = array_map(function ($name) use ($prefix) {
            $name = $prefix.$name;
            if (!$this->hasRole($name)) {
                throw new CasbinException('error: name1 or name2 does not exist');
            }

            return $name;
        }, [$name1, $name2]);

        $this->createRole($name1)->deleteRole(
            $this->createRole($name2)
        );
    }

    /**
     * determines whether role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     *
     * @param string $name1
     * @param string $name2
     * @param string ...$domain
     *
     * @return bool
     */
    public function hasLink(string $name1, string $name2, string ...$domain): bool
    {
        $prefix = self::getPrefix(...$domain);

        if ($name1 == $name2) {
            return true;
        }

        list($name1, $name2) = array_map(function ($name) use ($prefix) {
            return $prefix.$name;
        }, [$name1, $name2]);

        if (!$this->hasRole($name1) || !$this->hasRole($name2)) {
            return false;
        }

        return $this->createRole($name1)->hasRole($name2, $this->maxHierarchyLevel);
    }

    /**
     * gets the roles that a subject inherits.
     * domain is a prefix to the roles.
     *
     * @param string $name
     * @param string ...$domain
     *
     * @return array
     */
    public function getRoles(string $name, string ...$domain): array
    {
        $prefix = self::getPrefix(...$domain);

        $name = $prefix.$name;

        if (!$this->hasRole($name)) {
            return [];
        }

        $roles = $this->createRole($name)->getRoles();

        if ('' != $prefix) {
            array_walk($roles, function (&$role, $key, $len) {
                $role = \substr($role, $len);
            }, \strlen($prefix));
        }

        return $roles;
    }

    /**
     * gets the users that inherits a subject.
     * domain is an unreferenced parameter here, may be used in other implementations.
     *
     * @param string $name
     * @param string ...$domain
     *
     * @return array
     */
    public function getUsers(string $name, string ...$domain): array
    {
        $prefix = self::getPrefix(...$domain);

        $name = $prefix.$name;

        if (!$this->hasRole($name)) {
            // throw new CasbinException('error: name does not exist');
            return [];
        }

        $names = [];

        $len = \strlen($prefix);
        array_map(function ($role) use (&$names, $name, $len) {
            if ($role->hasDirectRole($name)) {
                $names[] = $len > 0 ? \substr($role->name, $len) : $role->name;
            }
        }, $this->allRoles);

        return $names;
    }

    /**
     * prints all the roles to log.
     */
    public function printRoles(): void
    {
        $line = [];

        array_map(function ($role) use (&$line) {
            if ($text = $role->toString()) {
                $line[] = $text;
            }
        }, $this->allRoles);

        Log::logPrint(implode(', ', $line));
    }

    /**
     * Get the prefix of the roles from domain.
     *
     * @param string ...$domain
     *
     * @return string
     */
    private static function getPrefix(string ...$domain): string
    {
        $size = \count($domain);

        if ($size > 1) {
            throw new CasbinException('error: domain should be 1 parameter');
        }

        return 1 == $size ? $domain[0].'::' : '';
    }
}
