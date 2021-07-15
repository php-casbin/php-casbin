<?php

declare(strict_types=1);

namespace Casbin\Persist;

/**
 * Interface WatcherUpdatable
 * WatcherUpdatable is the strengthen for Casbin watchers.
 *
 * @author ab1652759879@gmail.com
 */
interface WatcherUpdatable extends Watcher
{
    /**
     * updateForUpdatePolicy calls the update callback of other instances to synchronize their policy.
     * It is called after updatePolicy() method of Enforcer class
     *
     * @param string[] $oldRule the old rule.
     * @param string[] $newRule the new rule.
     * @return void
     */
    public function updateForUpdatePolicy(array $oldRule, array $newRule): void;

    /**
     * updateForUpdatePolicies calls the update callback of other instances to synchronize their policy.
     * It is called after updatePolicies() method of Enforcer class
     *
     * @param string[][] $oldRules
     * @param string[][] $newRules
     * @return void
     */
    public function updateForUpdatePolicies(array $oldRules, array $newRules): void;
}
