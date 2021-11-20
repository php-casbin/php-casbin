<?php

declare(strict_types=1);

namespace Casbin\Rbac\DefaultRoleManager;

use Casbin\Exceptions\CasbinException;
use Casbin\Log\Log;
use Casbin\Rbac\RoleManager as RoleManagerContract;
use Closure;

/**
 * Class RoleManager.
 * Provides a default implementation for the RoleManager interface.
 *
 * @author techlee@qq.com
 */
class RoleManager implements RoleManagerContract
{
    const DEFAULT_DOMAIN = 'casbin::default';

    /**
     * @var array<string, Roles>
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
        $this->allDomains[self::DEFAULT_DOMAIN] = new Roles();
        $this->maxHierarchyLevel = $maxHierarchyLevel;
        $this->hasPattern = false;
        $this->hasDomainPattern = false;
    }

    /**
     * Support use pattern in g.
     *
     * @param string $name
     * @param Closure $fn
     */
    public function addMatchingFunc(string $name, Closure $fn): void
    {
        $this->hasPattern = true;
        $this->matchingFunc = $fn;
    }

    /**
     * Support use domain pattern in g.
     *
     * @param string $name
     * @param Closure $fn
     */
    public function addDomainMatchingFunc(string $name, Closure $fn): void
    {
        $this->hasDomainPattern = true;
        $this->domainMatchingFunc = $fn;
    }

    /**
     * Clears all stored data and resets the role manager to the initial state.
     */
    public function clear(): void
    {
        $this->allDomains = [];
        $this->loadOrStoreRoles(self::DEFAULT_DOMAIN, new Roles());
    }

    /**
     * Adds the inheritance link between role: name1 and role: name2.
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
        if (count($domain) > 1) {
            throw new CasbinException('error: domain should be 1 parameter');
        }
        $domain = count($domain) == 0 ? [self::DEFAULT_DOMAIN] : $domain;

        $patternDomain = $this->getPatternDomain($domain[0]);

        foreach ($patternDomain as $domain) {
            $allRoles = &$this->loadOrStoreRoles($domain, new Roles());

            $role1 = &$allRoles->loadOrStore($name1, new Role($name1));
            $role2 = &$allRoles->loadOrStore($name2, new Role($name2));
            $role1->addRole($role2);

            if ($this->hasPattern) {
                foreach ($allRoles->toArray() as $key => $value) {
                    $matchingFunc = $this->matchingFunc;
                    if ($matchingFunc($key . '', $name1) && $name1 != $key) {
                        $valueRole = &$allRoles->loadOrStore($key . '', new Role($key . ''));
                        $valueRole->addRole($role1);
                    }
                    if ($matchingFunc($key . '', $name2) && $name2 != $key) {
                        $role2->addRole($value);
                    }
                    if ($matchingFunc($name1, $key . '') && $name1 != $key) {
                        $valueRole = &$allRoles->loadOrStore($key . '', new Role($key . ''));
                        $valueRole->addRole($role1);
                    }
                    if ($matchingFunc($name2, $key . '') && $name2 != $key) {
                        $role2->addRole($value);
                    }
                }
            }
        }
    }

    /**
     * Undocumented function
     *
     * @param string $domain
     * @return string[]
     */
    public function getPatternDomain(string $domain): array
    {
        $patternDomain = [$domain];
        if ($this->hasDomainPattern) {
            foreach ($this->allDomains as $key => $value) {
                $domainMatchingFunc = $this->domainMatchingFunc;
                if ($domain != $key . '' && $domainMatchingFunc($domain, $key . '')) {
                    $patternDomain[] = $key . '';
                }
            }
        }
        return $patternDomain;
    }

    /**
     * Deletes the inheritance link between role: name1 and role: name2.
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
        if (count($domain) > 1) {
            throw new CasbinException('error: domain should be 1 parameter');
        }
        $domain = count($domain) == 0 ? [self::DEFAULT_DOMAIN] : $domain;

        $allRoles = &$this->loadOrStoreRoles($domain[0], new Roles());

        if (is_null($allRoles->load($name1)) || is_null($allRoles->load($name2))) {
            throw new CasbinException('error: name1 or name2 does not exist');
        }

        $role1 = &$allRoles->loadOrStore($name1, new Role($name1));
        $role2 = &$allRoles->loadOrStore($name2, new Role($name2));

        $role1->deleteRole($role2);
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
     * @throws CasbinException
     */
    public function hasLink(string $name1, string $name2, string ...$domain): bool
    {
        if (count($domain) > 1) {
            throw new CasbinException('error: domain should be 1 parameter');
        }
        $domain = count($domain) == 0 ? [self::DEFAULT_DOMAIN] : $domain;

        if ($name1 == $name2) {
            return true;
        }

        $patternDomain = $this->getPatternDomain($domain[0]);

        foreach ($patternDomain as $domain) {
            $allRoles = &$this->loadOrStoreRoles($domain, new Roles());
            if (!$allRoles->hasRole($name1, $this->matchingFunc) || !$allRoles->hasRole($name2, $this->matchingFunc)) {
                continue;
            }

            if ($this->hasPattern) {
                $flag = false;
                foreach ($allRoles->toArray() as $key => $value) {
                    $matchingFunc = $this->matchingFunc;
                    if ($matchingFunc($name1, $key . '') && $value->hasRoleWithMatchingFunc($name2, $this->maxHierarchyLevel, $matchingFunc)) {
                        $flag = true;
                        break;
                    }
                }
                if ($flag) {
                    return true;
                }
                continue;
            }
            $role1 = &$allRoles->createRole($name1);
            $result = $role1->hasRole($name2, $this->maxHierarchyLevel);
            if ($result) {
                return true;
            }
            continue;
        }

        return false;
    }

    /**
     * Gets the roles that a subject inherits.
     * domain is a prefix to the roles.
     *
     * @param string $name
     * @param string ...$domain
     *
     * @return string[]
     * @throws CasbinException
     */
    public function getRoles(string $name, string ...$domain): array
    {
        if (count($domain) > 1) {
            throw new CasbinException('error: domain should be 1 parameter');
        }
        $domain = count($domain) == 0 ? [self::DEFAULT_DOMAIN] : $domain;

        $patternDomain = $this->getPatternDomain($domain[0]);

        $gottenRoles = [];

        foreach ($patternDomain as $domain) {
            $allRoles = &$this->loadOrStoreRoles($domain, new Roles());
            if (!$allRoles->hasRole($name, $this->matchingFunc)) {
                continue;
            }

            $gottenRoles = array_merge($gottenRoles, $allRoles->createRole($name)->getRoles());
        }

        $gottenRoles = array_unique($gottenRoles);
        return $gottenRoles;
    }

    /**
     * Gets the users that inherits a subject.
     * domain is an unreferenced parameter here, may be used in other implementations.
     *
     * @param string $name
     * @param string ...$domain
     *
     * @return string[]
     * @throws CasbinException
     */
    public function getUsers(string $name, string ...$domain): array
    {
        if (count($domain) > 1) {
            throw new CasbinException('error: domain should be 1 parameter');
        }
        $domain = count($domain) == 0 ? [self::DEFAULT_DOMAIN] : $domain;

        $patternDomain = $this->getPatternDomain($domain[0]);

        $names = [];
        foreach ($patternDomain as $domain) {
            $allRoles = &$this->loadOrStoreRoles($domain, new Roles());
            if (!$allRoles->hasRole($name, $this->matchingFunc)) {
                return [];
            }

            foreach ($allRoles->toArray() as $role) {
                if ($role->hasDirectRole($name)) {
                    $names[] = $role->name;
                }
            }
        }

        return $names;
    }

    /**
     * Prints all the roles to log.
     */
    public function printRoles(): void
    {
        $line = [];

        array_map(function (Roles $roles) use (&$line) {
            array_map(function (Role $role) use (&$line) {
                if ($text = $role->toString()) {
                    $line[] = $text;
                }
            }, $roles->toArray());
        }, $this->allDomains);

        Log::logPrint(implode(', ', $line));
    }

    /**
     * @param string $domain
     * @param Roles $roles
     *
     * @return Roles
     */
    protected function &loadOrStoreRoles(string $domain, Roles $roles): Roles
    {
        if (!isset($this->allDomains[$domain])) {
            $this->allDomains[$domain] = $roles;
        }

        return $this->allDomains[$domain];
    }
}
