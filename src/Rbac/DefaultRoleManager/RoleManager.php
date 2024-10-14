<?php

declare(strict_types=1);

namespace Casbin\Rbac\DefaultRoleManager;

use Casbin\Log\Logger\DefaultLogger;
use Casbin\Rbac\DefaultRoleManager\Traits\RoleManager as RoleManagerTrait;
use Casbin\Rbac\RoleManager as RoleManagerContract;
use Closure;

/**
 * Class RoleManager.
 * Provides a default implementation for the RoleManager interface.
 *
 * @author techlee@qq.com
 * @author 1692898084@qq.com
 */
class RoleManager implements RoleManagerContract
{
    use RoleManagerTrait;
    
    /**
     * RoleManager constructor.
     *
     * @param int $maxHierarchyLevel
     * @param Closure|null $matchingFunc
     */
    public function __construct(int $maxHierarchyLevel, ?Closure $matchingFunc = null)
    {
        $this->clear();
        $this->maxHierarchyLevel = $maxHierarchyLevel;
        $this->matchingFunc = $matchingFunc;
        $this->setLogger(new DefaultLogger());
    }

    /**
     * @param RoleManager $roleManager
     */
    public function copyFrom(RoleManager &$roleManager): void
    {
        $this->rangeLinks($roleManager->allRoles, function ($name1, $name2, $domain) {
            $this->addLink($name1, $name2, $domain);
        });
    }
}
