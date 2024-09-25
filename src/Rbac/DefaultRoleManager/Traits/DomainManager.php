<?php

declare(strict_types=1);

namespace Casbin\Rbac\DefaultRoleManager\Traits;

use Casbin\Log\Logger;
use Casbin\Rbac\DefaultRoleManager\RoleManager;
use Closure;

/**
 * Trait DomainManager.
 * Provides methods to manage roles in a domain.
 *
 * @author 1692898084@qq.com
 */
trait DomainManager
{
    /**
     * @var array<string, RoleManager>
     */
    protected array $rmMap = [];

    /**
     * @var int
     */
    protected int $maxHierarchyLevel = 10;

    /**
     * @var Closure|null $matchingFunc
     */
    protected ?Closure $matchingFunc = null;

    /**
     * @var Closure|null $domainMatchingFunc
     */
    protected ?Closure $domainMatchingFunc = null;

    /**
     * @var Logger
     */
    protected Logger $logger;

    /**
     * Sets the current logger.
     *
     * @param Logger $logger
     */
    public function setLogger(Logger $logger): void
    {
        $this->logger = $logger;
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
        foreach ($this->rmMap as $_ => &$rm) {
            $rm->addMatchingFunc($name, $fn);
        }
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
        foreach ($this->rmMap as $_ => &$rm) {
            $rm->addDomainMatchingFunc($name, $fn);
        }
        $this->rebuild();
    }

    /**
     * Clears the map of RoleManagers.
     */
    public function rebuild(): void
    {
        $rmMap = $this->rmMap;
        $this->clear();
        foreach ($rmMap as $domain => &$rm) {
            $rm->rangeSelfLinks(function ($name1, $name2, $_) use ($domain) {
                $this->addLink($name1, $name2, $domain);
            });
        }
    }

    /**
     * Clears all stored data and resets the role manager to the initial state.
     */
    public function clear(): void
    {
        $this->rmMap = [];
    }

    /**
     * Gets the domain from the given arguments.
     *
     * @param string|null $domain
     * @return string
     */
    public function getDomain(?string $domain = null): string
    {
        if (is_null($domain)) {
            return RoleManager::DEFAULT_DOMAIN;
        }
        return $domain;
    }

    /**
     * Determines whether a string matches a pattern.
     *
     * @param string $str
     * @param string $pattern
     * @return bool
     */
    public function match(string $str, string $pattern): bool
    {
        if ($str === $pattern) {
            return true;
        }

        if (!is_null($this->domainMatchingFunc)) {
            return call_user_func($this->domainMatchingFunc, $str, $pattern) === true;
        } else {
            return false;
        }
    }

    /**
     * Applies a callback to all RoleManagers that match the given domain.
     *
     * @param string $domain
     * @param Closure $fn
     */
    public function rangeAffectedRoleManagers(string $domain, Closure $fn): void
    {
        if (!is_null($this->domainMatchingFunc)) {
            foreach ($this->rmMap as $domain2 => &$rm) {
                if ($domain !== $domain2 && $this->match($domain2, $domain)) {
                    $fn($rm);
                }
            }
        }
    }


    /**
     * Gets the RoleManager for the given domain.
     *
     * @param string $domain
     * @param bool $store
     * @return RoleManager
     */
    public function &getRoleManager(string $domain, bool $store): RoleManager
    {
        if (isset($this->rmMap[$domain])) {
            return $this->rmMap[$domain];
        }

        $rm = new RoleManager($this->maxHierarchyLevel, $this->matchingFunc);
        if ($store) {
            $this->rmMap[$domain] = $rm;
        }
        if (!is_null($this->domainMatchingFunc)) {
            foreach ($this->rmMap as $domain2 => &$rm2) {
                if ($domain !== $domain2 && $this->match($domain, $domain2)) {
                    $rm->copyFrom($rm2);
                }
            }
        }

        return $rm;
    }

    /**
     * Adds the inheritance link between role: name1 and role: name2.
     * aka role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     *
     * @param string $name1
     * @param string $name2
     * @param string ...$domains
     */
    public function addLink(string $name1, string $name2, string ...$domains): void
    {
        $domain = $this->getDomain(...$domains);
        $rm = &$this->getRoleManager($domain, true);
        $rm->addLink($name1, $name2);
        $this->rangeAffectedRoleManagers($domain, function (&$rm) use ($name1, $name2) {
            $rm->addLink($name1, $name2);
        });
    }

    /**
     * Deletes the inheritance link between role: name1 and role: name2.
     * aka role: name1 does not inherit role: name2 any more.
     * domain is a prefix to the roles.
     *
     * @param string $name1
     * @param string $name2
     * @param string ...$domains
     */
    public function deleteLink(string $name1, string $name2, string ...$domains): void
    {
        $domain = $this->getDomain(...$domains);
        $rm = &$this->getRoleManager($domain, true);
        $rm->deleteLink($name1, $name2);

        $this->rangeAffectedRoleManagers($domain, function (&$rm) use ($name1, $name2) {
            $rm->deleteLink($name1, $name2);
        });
    }

    /**
     * Determines whether role: name1 inherits role: name2.
     * domain is a prefix to the roles.
     *
     * @param string $name1
     * @param string $name2
     * @param string ...$domains
     *
     * @return bool
     */
    public function hasLink(string $name1, string $name2, string ...$domains): bool
    {
        $domain = $this->getDomain(...$domains);
        $rm = &$this->getRoleManager($domain, false);
        return $rm->hasLink($name1, $name2, ...$domains);
    }

    /**
     * Gets the roles that a subject inherits.
     * domain is a prefix to the roles.
     *
     * @param string $name
     * @param string ...$domains
     *
     * @return string[]
     */
    public function getRoles(string $name, string ...$domains): array
    {
        $domain = $this->getDomain(...$domains);
        $rm = &$this->getRoleManager($domain, false);
        return $rm->getRoles($name, ...$domains);
    }

    /**
     * Gets the users that inherits a subject.
     * domain is an unreferenced parameter here, may be used in other implementations.
     *
     * @param string $name
     * @param string ...$domains
     *
     * @return string[]
     */
    public function getUsers(string $name, string ...$domains): array
    {
        $domain = $this->getDomain(...$domains);
        $rm = &$this->getRoleManager($domain, false);
        return $rm->getUsers($name, ...$domains);
    }


    /**
     * Converts the roles to a string array.
     *
     * @return string[]
     */
    public function toString(): array
    {
        $roles = [];

        foreach ($this->rmMap as $domain => &$rm) {
            $domainRoles = $rm->toString();
            $roles[] = sprintf('%s: %s', $domain, implode(', ', $domainRoles));
        }

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
        $domains = [];
        foreach ($this->rmMap as $domain => &$rm) {
            $roleGet = $rm->getRole($name);
            $role = $roleGet[0];
            $roleCreated = $roleGet[1];

            if (count($role->getUsers()) > 0 || count($role->getRoles()) > 0) {
                $domains[] = $domain;
            }

            if ($roleCreated) {
                $this->removeRole($role->name);
            }
        }
        return $domains;
    }

    /**
     * Gets all the domains.
     *
     * @return string[]
     */
    public function getAllDomains(): array
    {
        $domains = [];
        foreach ($this->rmMap as $domain => $_) {
            $domains[] = $domain;
        }
        return $domains;
    }
}
