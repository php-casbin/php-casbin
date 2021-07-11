<?php

namespace Casbin\Tests\Watcher;

use Casbin\Persist\WatcherUpdatable;

class SampleWatcherUpdatable extends SampleWatcher implements WatcherUpdatable
{
    /**
     * updateForUpdatePolicy calls the update callback of other instances to synchronize their policy.
     * It is called after updatePolicy() method of Enforcer class
     *
     * @param array $oldRule the old rule.
     * @param array $newRule the new rule.
     * @return void
     */
    public function updateForUpdatePolicy(array $oldRule, array $newRule): void
    {
        call_user_func($this->callback);
    }

    /**
     * updateForUpdatePolicies calls the update callback of other instances to synchronize their policy.
     * It is called after updatePolicies() method of Enforcer class
     *
     * @param array $oldRules
     * @param array $newRules
     * @return void
     */
    public function updateForUpdatePolicies(array $oldRules, array $newRules): void
    {
        call_user_func($this->callback);
    }
}
