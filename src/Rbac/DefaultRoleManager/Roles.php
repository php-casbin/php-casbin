<?php

declare(strict_types=1);

namespace Casbin\Rbac\DefaultRoleManager;

use Closure;

class Roles
{
    /**
     * @var array<string, Role>
     */
    private $roles = [];

    /**
     * @param string $name
     * @param Closure|null $matchingFunc
     *
     * @return bool
     */
    public function hasRole(string $name, ?Closure $matchingFunc): bool
    {
        $ok = false;
        if ($matchingFunc instanceof Closure) {
            foreach ($this->roles as $key => $role) {
                if ($matchingFunc($name, $key)) {
                    $ok = true;
                }
            }
        } else {
            $ok = isset($this->roles[$name]);
        }

        return $ok;
    }

    /**
     * @param string $name
     *
     * @return Role
     */
    public function &createRole(string $name): Role
    {
        $role = &$this->loadOrStore($name, new Role($name));
        return $role;
    }


    /**
     * @param string $name
     *
     * @return Role|null
     */
    public function load(string $name): ?Role
    {
        if (!isset($this->roles[$name])) {
            return null;
        }

        return $this->roles[$name];
    }

    /**
     * @param string $name
     * @param Role $role
     *
     * @return Role
     */
    public function &loadOrStore(string $name, Role $role): Role
    {
        if (!isset($this->roles[$name])) {
            $this->roles[$name] = $role;
        }

        return $this->roles[$name];
    }

    /**
     * @return array<string, Role>
     */
    public function toArray(): array
    {
        return $this->roles;
    }
}
