<?php

declare(strict_types=1);

namespace Casbin\Rbac\DefaultRoleManager;

use Casbin\Rbac\DefaultRoleManager\Traits\DomainManager as DomainManagerTrait;

/**
 * Class DomainManager.
 * Provides a default implementation for the RoleManager interface with domain support.
 *
 * @author 1692898084@qq.com
 */
class DomainManager extends RoleManager
{
    use DomainManagerTrait;
    
    /**
     * @var array<string, RoleManager>
     */
    protected array $rmMap = [];

    /**
     * DomainManager constructor.
     *
     * @param int $maxHierarchyLevel
     */
    public function __construct(int $maxHierarchyLevel)
    {
        parent::__construct($maxHierarchyLevel);
    }
}
