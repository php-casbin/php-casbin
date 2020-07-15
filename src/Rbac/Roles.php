<?php

declare(strict_types=1);

namespace Casbin\Rbac;

class Roles
{
    /**
     * @var array
     */
    public $roles = [];

    /**
     * @param string $name
     * @param mixed  $matchingFunc
     *
     * @return bool
     */
    public function hasRole(string $name, $matchingFunc): bool
    {
        if ($matchingFunc instanceof \Closure) {
            foreach ($this->roles as $key => $value) {
                if ($matchingFunc($name, (string) $key)) {
                    return true;
                }
            }
        } else {
            return isset($this->roles[$name]);
        }

        return false;
    }

    /**
     * @param string $name
     * @param mixed  $matchingFunc
     *
     * @return Role
     */
    public function createRole(string $name, $matchingFunc): Role
    {
        if (!isset($this->roles[$name])) {
            $this->roles[$name] = new Role($name);
        }

        if ($matchingFunc instanceof \Closure) {
            foreach ($this->roles as $key => $value) {
                if ($matchingFunc($name, (string) $key) && $name !== (string) $key) {
                    if (!isset($this->roles[$key])) {
                        $this->roles[$key] = new Role($key);
                    }
                    $this->roles[$name]->addRole($this->roles[$key]);

                    break;
                }
            }
        }

        if (!isset($this->roles[$name])) {
            $this->roles[$name] = new Role($name);
        }

        return $this->roles[$name];
    }
}
