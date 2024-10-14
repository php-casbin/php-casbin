<?php

declare(strict_types=1);

namespace Casbin\Rbac\DefaultRoleManager;

use Casbin\Exceptions\CasbinException;
use Casbin\Log\Logger\DefaultLogger;
use Casbin\Rbac\ConditionalRoleManager as ConditionalRoleManagerContract;
use Casbin\Rbac\DefaultRoleManager\Traits\RoleManager as RoleManagerTrait;
use Closure;
use Exception;

/**
 * Class ConditionalRoleManager.
 * Provides a default implementation for the ConditionalRoleManager interface.
 * 
 * @author 1692898084@qq.com
 */
class ConditionalRoleManager implements ConditionalRoleManagerContract
{
    use RoleManagerTrait;

    /**
     * ConditionalRoleManager constructor.
     *
     * @param int $maxHierarchyLevel
     * @param Closure|null $matchingFunc
     */
    public function __construct(int $maxHierarchyLevel, ?Closure $matchingFunc = null)
    {
        $this->clear();
        $this->maxHierarchyLevel = $maxHierarchyLevel;
        $this->setLogger(new DefaultLogger());
        $this->matchingFunc = $matchingFunc;
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
            return $this->hasLinkHelper($role->name, [$user->name => $user], $this->maxHierarchyLevel, ...$domain);
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
    protected function hasLinkHelper(string $targetName, array $roles, int $level, string ...$domain): bool
    {
        if ($level < 0 || count($roles) == 0) {
            return false;
        }

        $nextRoles = [];
        foreach ($roles as $name => $role) {
            if ($targetName === $role->name || (!is_null($this->matchingFunc) && $this->match($role->name, $targetName))) {
                return true;
            }

            try {
                $role->rangeRoles(function ($name, $nextRole) use (&$role, $domain, &$nextRoles) {
                    if (!$this->getNextRoles($role, $nextRole, $domain, $nextRoles)) {
                        throw new CasbinException('failed to get next roles');
                    };
                });
            } catch (CasbinException) {
                continue;
            }
        }

        return $this->hasLinkHelper($targetName, $nextRoles, $level - 1);
    }

    /**
     * @param Role $currentRole
     * @param Role $nextRole
     * @param array $domain
     * @param array $nextRoles
     * 
     * @return bool
     */
    protected function getNextRoles(Role $currentRole, Role $nextRole, array $domain, array &$nextRoles): bool
    {
        $passLinkConditionFunc = true;
        try {
            if (count($domain) === 0) {
                $linkConditionFunc = $this->getLinkConditionFunc($currentRole->name, $nextRole->name);
                if (!is_null($linkConditionFunc)) {
                    $params = $this->getLinkConditionFuncParams($currentRole->name, $nextRole->name);
                    $passLinkConditionFunc = $linkConditionFunc(...$params);
                }
            } else {
                $linkConditionFunc = $this->getDomainLinkConditionFunc($currentRole->name, $nextRole->name, $domain[0]);
                if (!is_null($linkConditionFunc)) {
                    $params = $this->getDomainLinkConditionFuncParams($currentRole->name, $nextRole->name, $domain[0]);
                    $passLinkConditionFunc = $linkConditionFunc(...$params);
                }
            }
        } catch (Exception $e) {
            $this->logger->logError($e, 'hasLinkHelper LinkCondition Error');
            return false;
        }

        if ($passLinkConditionFunc) {
            $nextRoles[$nextRole->name] = $nextRole;
        }

        return true;
    }

    /**
     * @param string $userName
     * @param string $roleName
     *
     * @return Closure|null
     */
    private function getLinkConditionFunc(string $userName, string $roleName): ?Closure
    {
        return $this->getDomainLinkConditionFunc($userName, $roleName, RoleManager::DEFAULT_DOMAIN);
    }

    /**
     * @param string $userName
     * @param string $roleName
     * @param string $domain
     * 
     * @return Closure|null
     */
    private function getDomainLinkConditionFunc(string $userName, string $roleName, string $domain): ?Closure
    {
        $userGet = &$this->getRole($userName);
        $roleGet = &$this->getRole($roleName);
        $user = &$userGet[0];
        $role = &$roleGet[0];
        $userCreated = $userGet[1];
        $roleCreated = $roleGet[1];

        if ($userCreated) {
            $this->removeRole($user->name);
            return null;
        }

        if ($roleCreated) {
            $this->removeRole($role->name);
            return null;
        }

        return $user->getLinkConditionFunc($role, $domain);
    }

    /**
     * @param string $userName
     * @param string $roleName
     * 
     * @return array|null
     */
    private function getLinkConditionFuncParams(string $userName, string $roleName): ?array
    {
        return $this->getDomainLinkConditionFuncParams($userName, $roleName, RoleManager::DEFAULT_DOMAIN);
    }

    /**
     * @param string $userName
     * @param string $roleName
     * @param string $domain
     * 
     * @return array|null
     */
    private function getDomainLinkConditionFuncParams(string $userName, string $roleName, string $domain): ?array
    {
        $userGet = &$this->getRole($userName);
        $roleGet = &$this->getRole($roleName);
        $user = &$userGet[0];
        $role = &$roleGet[0];
        $userCreated = $userGet[1];
        $roleCreated = $roleGet[1];

        if ($userCreated) {
            $this->removeRole($user->name);
            return null;
        }

        if ($roleCreated) {
            $this->removeRole($role->name);
            return null;
        }

        return $user->getLinkConditionFuncParams($role, $domain);
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
        $this->addDomainLinkConditionFunc($userName, $roleName, RoleManager::DEFAULT_DOMAIN, $linkConditionFunc);
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
        $userGet = &$this->getRole($userName);
        $roleGet = &$this->getRole($roleName);
        $user = &$userGet[0];
        $role = &$roleGet[0];

        $user->addLinkConditionFunc($role, $domain, $linkConditionFunc);
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
        $this->setDomainLinkConditionFuncParams($userName, $roleName, RoleManager::DEFAULT_DOMAIN, ...$params);
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
        $userGet = &$this->getRole($userName);
        $roleGet = &$this->getRole($roleName);
        $user = &$userGet[0];
        $role = &$roleGet[0];

        $user->setLinkConditionFuncParams($role, $domain, ...$params);
    }

    /**
     * @param ConditionalRoleManager $roleManager
     */
    public function copyFrom(ConditionalRoleManager &$roleManager): void
    {
        $this->rangeLinks($roleManager->allRoles, function ($name1, $name2, $domain) {
            $this->addLink($name1, $name2, $domain);
        });
    }
}
