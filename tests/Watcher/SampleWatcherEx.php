<?php

namespace Casbin\Tests\Watcher;

use Casbin\Persist\WatcherEx;
use Casbin\Model\Model;

class SampleWatcherEx extends SampleWatcher implements WatcherEx
{
    /**
     * updateForAddPolicy calls the update callback of other instances to synchronize their policy.
     * It is called after addPolicy() method of Enforcer class
     *
     * @param string $sec
     * @param string $ptype
     * @param string ...$params
     * @return void
     */
    public function updateForAddPolicy(string $sec, string $ptype, string ...$params): void
    {
        call_user_func($this->callback);
    }

    /**
     * updateForRemovePolicy calls the update callback of other instances to synchronize their policy.
     * It is called after removePolicy() method of Enforcer class
     *
     * @param string $sec
     * @param string $ptype
     * @param string ...$params
     * @return void
     */
    public function updateForRemovePolicy(string $sec, string $ptype, string ...$params): void
    {
        call_user_func($this->callback);
    }

    /**
     * updateForRemoveFilteredPolicy calls the update callback of other instances to synchronize their policy.
     * It is called after removeFilteredNamedGroupingPolicy() method of Enforcer class
     *
     * @param string $sec
     * @param string $ptype
     * @param integer $fieldIndex
     * @param string ...$fieldValues
     * @return void
     */
    public function updateForRemoveFilteredPolicy(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues): void
    {
        call_user_func($this->callback);
    }

    /**
     * updateForSavePolicy calls the update callback of other instances to synchronize their policy.
     * It is called after removeFilteredNamedGroupingPolicy() method of Enforcer class
     *
     * @param Model $model
     * @return void
     */
    public function updateForSavePolicy(Model $model): void
    {
        call_user_func($this->callback);
    }
}
