<?php

declare(strict_types=1);

namespace Casbin\Rbac\DefaultRoleManager;

use Casbin\Exceptions\CasbinException;
use Casbin\Rbac\Role;
use Casbin\Rbac\RoleManager as RoleManagerContract;
use Casbin\Log\Log;
use Casbin\Rbac\Roles;
use Closure;

/**
 * Class RoleManager.
 * provides a default implementation for the RoleManager interface.
 *
 * @author techlee@qq.com
 */
class RoleManager implements RoleManagerContract
{
    const DEFAULTDOMAIN = 'casbin::default';

    /**
     * @var array
     */
    protected $allDomains;

    /**
     * @var int
     */
    protected $maxHierarchyLevel;

    /**
     * @var bool
     */
    protected $hasPattern;

    /**
     * @var Closure
     */
    protected $matchingFunc;

    /**
     * @var bool
     */
    protected $hasDomainPattern;

    /**
     * @var Closure
     */
    protected $domainMatchingFunc;

    /**
     * RoleManager constructor.
     *
     * @param int $maxHierarchyLevel
     */
    public function __construct(int $maxHierarchyLevel)
    {
        $this->allDomains[self::DEFAULTDOMAIN] = new Roles();
        $this->maxHierarchyLevel = $maxHierarchyLevel;
        $this->hasPattern = false;
        $this->hasDomainPattern = false;
    }

    /**
     * support use pattern in g.
     *
     * @param string  $name
     * @param Closure $fn
     */
    public function addMatchingFunc(string $name, Closure $fn): void
    {
        $this->hasPattern = true;
        $this->matchingFunc = $fn;
    }

    /**
     * support use domain pattern in g.
     *
     * @param string  $name
     * @param Closure $fn
     */
    public function addDomainMatchingFunc(string $name, Closure $fn): void
    {
        $this->hasDomainPattern = true;
        $this->domainMatchingFunc = $fn;
    }

    /**
     * @param string $domain
     *
     * @return Roles
     */
    protected function generateTempRoles(string $domain): Roles
    {
        $this->loadOrStormRoles($domain);

        $patternDomain = [$domain];

        if ($this->hasDomainPattern) {
            foreach ($this->allDomains as $key => $allDomain) {
                $fu = $this->domainMatchingFunc;
                if ($fu($domain, (string) $key)) {
                    $patternDomain = array_merge($patternDomain, [$key]);
                    $patternDomain[] = $key;
                }
            }
        }

        $allRoles = new Roles();

        foreach ($patternDomain as $domain) {
            $values = $this->loadOrStormRoles($domain);
            foreach ($values->roles as $key => $value) {
                /** @var Role $role2 */
                $role2 = $value;
                $role1 = $allRoles->createRole($role2->name, $this->matchingFunc);
                foreach ($role2->getRoles() as $v) {
                    $role3 = $allRoles->createRole($v, $this->matchingFunc);
                    $role1->addRole($role3);
                }
            }
        }

        return $allRoles;
    }

    /**
     * clears all stored data and resets the role manager to the initial state.
     */
    public function clear(): void
    {
        $this->allDomains = [];
        $this->allDomains[self::DEFAULTDOMAIN] = new Roles();
    }

    /**
     * adds the inheritance link between role: name1 and role: name2.
     * aka role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     *
     * @param string $name1
     * @param string $name2
     * @param string ...$domain
     *
     * @throws CasbinException
     */
    public function addLink(string $name1, string $name2, string ...$domain): void
    {
        $domain = $this->checkDomainLength($domain);
        $allRoles = $this->loadOrStormRoles($domain[0]);
        $role1 = $this->loadOrStormRole($allRoles, $name1);
        $role2 = $this->loadOrStormRole($allRoles, $name2);
        $role1->addRole($role2);
    }

    /**
     * deletes the inheritance link between role: name1 and role: name2.
     * aka role: name1 does not inherit role: name2 any more.
     * domain is a prefix to the roles.
     *
     * @param string $name1
     * @param string $name2
     * @param string ...$domain
     *
     * @throws CasbinException
     */
    public function deleteLink(string $name1, string $name2, string ...$domain): void
    {
        $domain = $this->checkDomainLength($domain);
        $allRoles = $this->loadOrStormRoles($domain[0]);

        if (!isset($allRoles->roles[$name1]) || !isset($allRoles->roles[$name2])) {
            throw new CasbinException('error: name1 or name2 does not exist');
        }

        $role1 = $this->loadOrStormRole($allRoles, $name1);
        $role2 = $this->loadOrStormRole($allRoles, $name2);
        $role1->deleteRole($role2);
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
     *
     * @throws CasbinException
     */
    public function hasLink(string $name1, string $name2, string ...$domain): bool
    {
        $domain = $this->checkDomainLength($domain);

        if ($name1 == $name2) {
            return true;
        }

        $allRoles = $this->checkHasDomainPatternOrHasPattern($domain[0]);

        if (!$allRoles->hasRole($name1, $this->matchingFunc) || !$allRoles->hasRole($name2, $this->matchingFunc)) {
            return false;
        }

        $role1 = $allRoles->createRole($name1, $this->matchingFunc);

        return $role1->hasRole($name2, $this->maxHierarchyLevel);
    }

    /**
     * gets the roles that a subject inherits.
     * domain is a prefix to the roles.
     *
     * @param string $name
     * @param string ...$domain
     *
     * @return array
     *
     * @throws CasbinException
     */
    public function getRoles(string $name, string ...$domain): array
    {
        $domain = $this->checkDomainLength($domain);
        $allRoles = $this->checkHasDomainPatternOrHasPattern($domain[0]);

        if (!$allRoles->hasRole($name, $this->matchingFunc)) {
            return [];
        }
        $roles = $allRoles->createRole($name, $this->matchingFunc)->getRoles();

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
     *
     * @throws CasbinException
     */
    public function getUsers(string $name, string ...$domain): array
    {
        $domain = $this->checkDomainLength($domain);
        $allRoles = $this->checkHasDomainPatternOrHasPattern($domain[0]);

        if (!$allRoles->hasRole($name, $this->domainMatchingFunc)) {
            // throw new CasbinException('error: name does not exist');
            return [];
        }

        $names = [];
        /** @var Role $allRole */
        foreach ($allRoles->roles as $allRole) {
            if ($allRole->hasDirectRole($name)) {
                $names[] = $allRole->name;
            }
        }

        return $names;
    }

    /**
     * prints all the roles to log.
     */
    public function printRoles(): void
    {
        $line = [];

        array_map(function ($roles) use (&$line) {
            array_map(function ($role) use (&$line) {
                if ($text = $role->toString()) {
                    $line[] = $text;
                }
            }, $roles->roles);
        }, $this->allDomains);

        Log::logPrint(implode(', ', $line));
    }

    /**
     * @param array $domain
     *
     * @return array|string[]
     *
     * @throws CasbinException
     */
    protected function checkDomainLength(array $domain): array
    {
        if (0 === count($domain)) {
            $domain = [self::DEFAULTDOMAIN];
        } elseif (count($domain) > 1) {
            throw new CasbinException('error: domain should be 1 parameter');
        }

        return $domain;
    }

    /**
     * @param string $domain
     *
     * @return Roles
     */
    protected function loadOrStormRoles(string $domain): Roles
    {
        if (!isset($this->allDomains[$domain])) {
            $this->allDomains[$domain] = new Roles();
        }

        return $this->allDomains[$domain];
    }

    /**
     * @param Roles  $allRoles
     * @param string $name
     *
     * @return Role
     */
    protected function loadOrStormRole(Roles $allRoles, string $name): Role
    {
        if (!isset($allRoles->roles[$name])) {
            $allRoles->roles[$name] = new Role($name);
        }

        return $allRoles->roles[$name];
    }

    /**
     * @param $domain
     *
     * @return Roles
     */
    protected function checkHasDomainPatternOrHasPattern($domain): Roles
    {
        if ($this->hasDomainPattern || $this->hasPattern) {
            $allRoles = $this->generateTempRoles($domain);
        } else {
            $allRoles = $this->loadOrStormRoles($domain);
        }

        return $allRoles;
    }
}
