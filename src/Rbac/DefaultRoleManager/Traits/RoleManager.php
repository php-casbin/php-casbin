<?php

declare(strict_types=1);

namespace Casbin\Rbac\DefaultRoleManager\Traits;

use Casbin\Rbac\DefaultRoleManager\Role;
use Casbin\Rbac\RoleManager as RoleManagerContract;
use Closure;

/**
 * Trait RoleManager.
 * Provides methods to manage roles.
 *
 * @author techlee@qq.com
 * @author 1692898084@qq.com
 */
trait RoleManager
{
    use BaseManager;

    /**
     * @var array<string, Role>
     */
    protected array $allRoles = [];

    /**
     * Clears the map of Roles.
     *
     * @return void
     */
    protected function rebuild(): void
    {
        $roles = $this->allRoles;
        $this->clear();
        $this->rangeLinks($roles, function (string $name1, string $name2, string $domain) {
            $this->addLink($name1, $name2, $domain);
        });
    }

    /**
     * Determines whether a string matches a pattern.
     *
     * @param string $str
     * @param string $pattern
     *
     * @return bool
     */
    public function match(string $str, string $pattern): bool
    {
        if ($str === $pattern) {
            return true;
        }

        if (!is_null($this->matchingFunc)) {
            return call_user_func($this->matchingFunc, $str, $pattern) === true;
        }
        return false;
    }

    /**
     * Applies a callback to all roles that match the given name or pattern.
     *
     * @param string $name
     * @param bool $isPattern
     * @param Closure $fn
     *
     * @return void
     */
    protected function rangeMatchRoles(string $name, bool $isPattern, Closure $fn): void
    {
        foreach ($this->allRoles as $name2 => &$role) {
            if ($isPattern && $name !== $name2 && $this->match($name2, $name)) {
                $fn($role);
            } else if (!$isPattern && $name !== $name2 && $this->match($name, $name2)) {
                $fn($role);
            }
        }
    }

    /**
     * Gets the role by given name.
     *
     * @param string $name
     *
     * @return array
     */
    public function &getRole(string $name): array
    {
        if (isset($this->allRoles[$name])) {
            $res = [&$this->allRoles[$name], false];
            return $res;
        }

        $role = new Role($name);
        $this->allRoles[$name] = $role;

        if (!is_null($this->matchingFunc)) {
            $this->rangeMatchRoles($name, false, function (Role &$r) use (&$role) {
                $r->addMatch($role);
            });

            $this->rangeMatchRoles($name, true, function (Role &$r) use (&$role) {
                $role->addMatch($r);
            });
        }

        $res = [&$this->allRoles[$name], true];
        return $res;
    }

    /**
     * @param array $map
     * @param string $name
     *
     * @return mixed
     */
    protected function loadAndDelete(array &$map, string $name): mixed
    {
        if (isset($map[$name])) {
            $value = $map[$name];
            unset($map[$name]);
        }
        return $value ?? null;
    }

    /**
     * Removes the role with the given name.
     *
     * @param string $name
     */
    protected function removeRole(string $name): void
    {
        $role = $this->loadAndDelete($this->allRoles, $name);
        if (!is_null($role)) {
            $role->removeMatches();
        }
    }

    /**
     * Support use pattern in g.
     *
     * @param string $name
     * @param Closure $fn
     */
    public function addMatchingFunc(string $name, Closure $fn): void
    {
        $this->matchingFunc = $fn;
        $this->rebuild();
    }

    /**
     * Support use domain pattern in g.
     *
     * @param string $name
     * @param Closure $fn
     */
    public function addDomainMatchingFunc(string $name, Closure $fn): void
    {
        $this->domainMatchingFunc = $fn;
    }

    /**
     * Clears all stored data and resets the role manager to the initial state.
     */
    public function clear(): void
    {
        $this->allRoles = [];
    }

    /**
     * Adds the inheritance link between role: name1 and role: name2.
     * aka role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     *
     * @param string $name1
     * @param string $name2
     * @param string ...$domain
     */
    public function addLink(string $name1, string $name2, string ...$domain): void
    {
        $userGet = &$this->getRole($name1);
        $roleGet = &$this->getRole($name2);
        $userGet[0]->addRole($roleGet[0]);
    }

    /**
     * Deletes the inheritance link between role: name1 and role: name2.
     * aka role: name1 does not inherit role: name2 any more.
     * domain is a prefix to the roles.
     *
     * @param string $name1
     * @param string $name2
     * @param string ...$domain
     */
    public function deleteLink(string $name1, string $name2, string ...$domain): void
    {
        $userGet = &$this->getRole($name1);
        $roleGet = &$this->getRole($name2);
        $userGet[0]->removeRole($roleGet[0]);
    }

    /**
     * Determines whether role: name1 inherits role: name2.
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
        if ($name1 == $name2 || (!is_null($this->matchingFunc) && $this->match($name1, $name2))) {
            return true;
        }

        $userGet = &$this->getRole($name1);
        $roleGet = &$this->getRole($name2);
        $user = &$userGet[0];
        $role = &$roleGet[0];
        $userCreated = $userGet[1];
        $roleCreated = $roleGet[1];

        try {
            return $this->hasLinkHelper($role->name, [$user->name => $user], $this->maxHierarchyLevel);
        } finally {
            if ($userCreated) {
                $this->removeRole($user->name);
            }

            if ($roleCreated) {
                $this->removeRole($role->name);
            }
        }
    }

    /**
     * @param string $targetName
     * @param array $roles
     * @param int $level
     * @return bool
     */
    protected function hasLinkHelper(string $targetName, array $roles, int $level): bool
    {
        if ($level < 0 || count($roles) == 0) {
            return false;
        }

        $nextRoles = [];
        foreach ($roles as $name => $role) {
            if ($targetName === $role->name || (!is_null($this->matchingFunc) && $this->match($role->name, $targetName))) {
                return true;
            }

            $role->rangeRoles(function ($name, &$role) use (&$nextRoles) {
                $nextRoles[$name] = $role;
            });
        }

        return $this->hasLinkHelper($targetName, $nextRoles, $level - 1);
    }

    /**
     * Gets the roles that a subject inherits.
     * domain is a prefix to the roles.
     *
     * @param string $name
     * @param string ...$domain
     *
     * @return string[]
     */
    public function getRoles(string $name, string ...$domain): array
    {
        $userGet = &$this->getRole($name);
        $user = &$userGet[0];
        $userCreated = $userGet[1];
        try {
            return $user->getRoles();
        } finally {
            if ($userCreated) {
                $this->removeRole($user->name);
            }
        }
    }

    /**
     * Gets the users that inherits a subject.
     * domain is an unreferenced parameter here, may be used in other implementations.
     *
     * @param string $name
     * @param string ...$domain
     *
     * @return string[]
     */
    public function getUsers(string $name, string ...$domain): array
    {
        $roleGet = &$this->getRole($name);
        $role = &$roleGet[0];
        $roleCreated = $roleGet[1];
        try {
            return $role->getUsers();
        } finally {
            if ($roleCreated) {
                $this->removeRole($role->name);
            }
        }
    }

    /**
     * Converts the roles to a string array.
     *
     * @return array
     */
    public function toString(): array
    {
        $roles = [];

        $roles = array_map(function (&$role) {
            return $role->toString();
        }, $this->allRoles);

        return $roles;
    }

    /**
     * Prints all the roles to log.
     */
    public function printRoles(): void
    {
        if (!$this->logger->isEnabled()) {
            return;
        }
        $roles = $this->toString();
        $this->logger->logRole($roles);
    }

    /**
     * Gets the domains that a subject inherits.
     * 
     * @param string $name
     * 
     * @return string[]
     */
    public function getDomains(string $name): array
    {
        return [RoleManagerContract::DEFAULT_DOMAIN];
    }

    /**
     * Gets all the domains.
     * 
     * @return string[]
     */
    public function getAllDomains(): array
    {
        return [RoleManagerContract::DEFAULT_DOMAIN];
    }

    /**
     * Applies a callback to all the links between users and roles.
     *
     * @param array &$users
     * @param Closure $fn
     */
    public function rangeLinks(array &$users, Closure $fn): void
    {
        foreach ($users as &$user) {
            foreach ($user->roles as $roleName => $_) {
                $fn($user->name, $roleName, RoleManagerContract::DEFAULT_DOMAIN);
            }
        }
    }

    /**
     * Applies a callback to all the links between users and roles in itself.
     *
     * @param Closure $fn
     */
    public function rangeSelfLinks(Closure $fn): void
    {
        $this->rangeLinks($this->allRoles, $fn);
    }
}
