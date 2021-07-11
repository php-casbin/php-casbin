<?php

namespace Casbin\Tests\Watcher;

use Casbin\Persist\Watcher;
use Closure;

class SampleWatcher implements Watcher
{
    protected $callback;

    /**
     * Sets the callback function that the watcher will call when the policy in DB has been changed by other instances.
     * A classic callback is loadPolicy() method of Enforcer class.
     *
     * @param Closure $func
     */
    public function setUpdateCallback(Closure $func): void
    {
        $this->callback = $func;
    }

    /**
     * update calls the update callback of other instances to synchronize their policy.
     * It is usually called after changing the policy in DB, like savePolicy() method of Enforcer class,
     * addPolicy(), removePolicy(), etc.
     */
    public function update(): void
    {
        call_user_func($this->callback);
    }

    /**
     * Close stops and releases the watcher, the callback function will not be called any more.
     */
    public function close(): void
    {
    }
}
