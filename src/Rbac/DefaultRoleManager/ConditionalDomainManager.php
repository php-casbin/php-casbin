<?php

declare(strict_types=1);

namespace Casbin\Rbac\DefaultRoleManager;

use Casbin\Rbac\DefaultRoleManager\Traits\DomainManager as DomainManagerTrait;
use Closure;

/**
 * Class ConditionalDomainManager.
 * Provides a default implementation for the ConditionalRoleManager interface with domain support.
 *
 * @author 1692898084@qq.com
 */
class ConditionalDomainManager extends ConditionalRoleManager
{
    use DomainManagerTrait;

    /**
     * @var array<string, ConditionalRoleManager>
     */
    protected array $rmMap = [];

    /**
     * ConditionalDomainManager constructor.
     * 
     * @param int $maxHierarchyLevel
     */
    public function __construct(int $maxHierarchyLevel)
    {
        parent::__construct($maxHierarchyLevel);
    }

    /**
     * Gets the RoleManager for the given domain.
     *
     * @param string $domain
     * @param bool $store
     * @return ConditionalRoleManager
     */
    public function &getRoleManager(string $domain, bool $store): ConditionalRoleManager
    {
        if (isset($this->rmMap[$domain])) {
            return $this->rmMap[$domain];
        }

        $rm = new ConditionalRoleManager($this->maxHierarchyLevel, $this->matchingFunc);
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
        $rm = &$this->getRoleManager($domain, true);
        return $rm->hasLink($name1, $name2, ...$domains);
    }

    /**
     * AddLinkConditionFunc Add condition function fn for Link userName->roleName,
     * when fn returns true, Link is valid, otherwise invalid
     *
     * @param string $userName
     * @param string $roleName
     * @param Closure $linkConditionFunc
     */
    public function addLinkConditionFunc(string $userName, string $roleName, Closure $linkConditionFunc): void
    {
        foreach ($this->rmMap as $_ => &$rm) {
            $rm->addLinkConditionFunc($userName, $roleName, $linkConditionFunc);
        }
    }

    /**
     * AddDomainLinkConditionFunc Add condition function fn for Link userName-> {roleName, domain},
     * when fn returns true, Link is valid, otherwise invalid
     *
     * @param string $userName
     * @param string $roleName
     * @param string $domain
     * @param Closure $linkConditionFunc
     */
    public function addDomainLinkConditionFunc(string $userName, string $roleName, string $domain, Closure $linkConditionFunc): void
    {
        foreach ($this->rmMap as $_ => &$rm) {
            $rm->addDomainLinkConditionFunc($userName, $roleName, $domain, $linkConditionFunc);
        }
    }

    /**
     * SetLinkConditionFuncParams Sets the parameters of the condition function fn for Link userName->roleName
     *
     * @param string $userName
     * @param string $roleName
     * @param string ...$params
     */
    public function setLinkConditionFuncParams(string $userName, string $roleName, string ...$params): void
    {
        foreach ($this->rmMap as $_ => &$rm) {
            $rm->setLinkConditionFuncParams($userName, $roleName, ...$params);
        }
    }

    /**
     * SetDomainLinkConditionFuncParams Sets the parameters of the condition function fn
     * for Link userName->{roleName, domain}
     *
     * @param string $userName
     * @param string $roleName
     * @param string $domain
     * @param string ...$params
     */
    public function setDomainLinkConditionFuncParams(string $userName, string $roleName, string $domain, string ...$params): void
    {
        foreach ($this->rmMap as $_ => &$rm) {
            $rm->setDomainLinkConditionFuncParams($userName, $roleName, $domain, ...$params);
        }
    }
}
