<?php

declare(strict_types=1);

namespace Casbin\Rbac\DefaultRoleManager\Traits;

use Casbin\Log\Logger;
use Closure;

/**
 * Trait BaseRoleManager.
 * Provides basic methods for role management.
 *
 * @author 1692898084@qq.com
 */
trait BaseManager
{
    /**
     * @var int
     */
    protected int $maxHierarchyLevel = 10;

    /**
     * @var Closure|null
     */
    protected ?Closure $matchingFunc = null;

    /**
     * @var Closure|null
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
     *
     * @return void
     */
    public function setLogger(Logger $logger): void
    {
        $this->logger = $logger;
    }
}
