<?php

declare(strict_types=1);

namespace Casbin\Rbac;

use Closure;

/**
 * Interface ConditionalRoleManager.
 * Provides interface to define the operations for managing roles with conditions.
 * 
 * @author 1692898084@qq.com
 */
interface ConditionalRoleManager extends RoleManager
{
    /**
     * AddLinkConditionFunc Add condition function fn for Link userName->roleName,
     * when fn returns true, Link is valid, otherwise invalid
     *
     * @param string $userName
     * @param string $roleName
     * @param Closure $linkConditionFunc
     */
    public function addLinkConditionFunc(string $userName, string $roleName, Closure $linkConditionFunc): void;

    /**
     * SetLinkConditionFuncParams Sets the parameters of the condition function fn for Link userName->roleName
     *
     * @param string $userName
     * @param string $roleName
     * @param string ...$params
     */
    public function setLinkConditionFuncParams(string $userName, string $roleName, string ...$params): void;

    /**
     * AddDomainLinkConditionFunc Add condition function fn for Link userName-> {roleName, domain},
     * when fn returns true, Link is valid, otherwise invalid
     *
     * @param string $userName
     * @param string $roleName
     * @param string $domain
     * @param Closure $linkConditionFunc
     */
    public function addDomainLinkConditionFunc(string $userName, string $roleName, string $domain, Closure $linkConditionFunc): void;

    /**
     * SetDomainLinkConditionFuncParams Sets the parameters of the condition function fn
     * for Link userName->{roleName, domain}
     *
     * @param string $userName
     * @param string $roleName
     * @param string $domain
     * @param string ...$params
     */
    public function setDomainLinkConditionFuncParams(string $userName, string $roleName, string $domain, string ...$params): void;
}
