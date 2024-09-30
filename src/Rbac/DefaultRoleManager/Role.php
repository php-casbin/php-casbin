<?php

declare(strict_types=1);

namespace Casbin\Rbac\DefaultRoleManager;

use Casbin\Util\Util;
use Closure;

/**
 * Role.
 * Represents the data structure for a role in RBAC.
 *
 * @author techlee@qq.com
 * @author 1692898084@qq.com
 */
class Role
{
    /**
     * @var string
     */
    public string $name = '';

    /**
     * @var array<string, Role>
     */
    public array $roles = [];

    /**
     * @var array<string, Role>
     */
    private array $users = [];

    /**
     * @var array<string, Role>
     */
    private array $matched = [];

    /**
     * @var array<string, Role>
     */
    private array $matchedBy = [];

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
        $this->roles[$role->name] = $role;
        $role->addUser($this);
    }

    /**
     * @param self $role
     */
    public function removeRole(self $role): void
    {
        unset($this->roles[$role->name]);
        $role->removeUser($this);
    }

    /**
     * @param self $user
     */
    public function addUser(self $user): void
    {
        $this->users[$user->name] = $user;
    }

    /**
     * @param self $user
     */
    public function removeUser(self $user): void
    {
        unset($this->users[$user->name]);
    }


    /**
     * @param self $role
     */
    public function addMatch(self $role): void
    {
        $this->matched[$role->name] = $role;
        $role->matchedBy[$this->name] = $this;
    }

    /**
     * @param self $role
     */
    public function removeMatch(self $role): void
    {
        unset($this->matched[$role->name]);
        unset($role->matchedBy[$this->name]);
    }

    /**
     * RemoveMatches removes all matches of this role.
     */
    public function removeMatches(): void
    {
        foreach ($this->matched as &$role) {
            $this->removeMatch($role);
        }
        foreach ($this->matchedBy as &$role) {
            $role->removeMatch($this);
        }
    }


    /**
     * Applies a callback to all roles that this role matches.
     *
     * @param Closure $fn
     */
    public function rangeRoles(Closure $fn): void
    {
        array_walk($this->roles, function (&$role, $name) use ($fn) {
            $fn($name, $role);
        });

        array_walk($this->roles, function ($role) use ($fn) {
            array_walk($role->matched, function (&$value, $key) use ($fn) {
                $fn($key, $value);
            });
        });

        array_walk($this->matchedBy, function ($role) use ($fn) {
            array_walk($role->roles, function (&$value, $key) use ($fn) {
                $fn($key, $value);
            });
        });
    }

    /**
     * Applies a callback to all users that this role matches.
     *
     * @param Closure $fn
     */
    public function rangeUsers(Closure $fn): void
    {
        array_walk($this->users, function (&$user, $name) use ($fn) {
            $fn($name, $user);
        });

        array_walk($this->users, function ($user) use ($fn) {
            array_walk($user->matched, function (&$value, $key) use ($fn) {
                $fn($key, $value);
            });
        });

        array_walk($this->matchedBy, function ($user) use ($fn) {
            array_walk($user->users, function (&$value, $key) use ($fn) {
                $fn($key, $value);
            });
        });
    }

    /**
     * Converts the role to a string.
     *
     * @return string
     */
    public function toString(): string
    {
        $len = count($this->roles);

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
        $names = [];
        $this->rangeRoles(function ($name, $role) use (&$names) {
            $names[] = $name;
        });
        return Util::removeDumplicateElement($names);
    }

    /**
     * @return string[]
     */
    public function getUsers(): array
    {
        $names = [];
        $this->rangeUsers(function ($name, $user) use (&$names) {
            $names[] = $name;
        });
        return $names;
    }
}
