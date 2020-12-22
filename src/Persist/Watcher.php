<?php

declare(strict_types=1);

namespace Casbin\Persist;

use Closure;

/**
 * Interface Watcher
 * The interface for Casbin watchers.
 *
 * @author techlee@qq.com
 */
interface Watcher
{
    /**
     * Sets the callback function that the watcher will call when the policy in DB has been changed by other instances.
     * A classic callback is Enforcer.LoadPolicy().
     *
     * @param Closure $func
     */
    public function setUpdateCallback(Closure $func): void;

    /**
     * Update calls the update callback of other instances to synchronize their policy.
     * It is usually called after changing the policy in DB, like Enforcer.SavePolicy(),
     * Enforcer.AddPolicy(), Enforcer.RemovePolicy(), etc.
     */
    public function update(): void;

    /**
     * Close stops and releases the watcher, the callback function will not be called any more.
     */
    public function close(): void;
}
