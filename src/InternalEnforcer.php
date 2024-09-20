<?php

declare(strict_types=1);

namespace Casbin;

use Casbin\Exceptions\NotImplementedException;
use Casbin\Model\Policy;
use Casbin\Persist\BatchAdapter;
use Casbin\Persist\UpdatableAdapter;
use Casbin\Persist\WatcherEx;
use Casbin\Persist\WatcherUpdatable;

/**
 * InternalEnforcer = CoreEnforcer + Internal API.
 *
 * @author techlee@qq.com
 */
class InternalEnforcer extends CoreEnforcer
{
    /**
     * @return bool
     */
    protected function shouldPersist(): bool
    {
        return !is_null($this->adapter) && $this->autoSave;
    }

    /**
     * @return bool
     */
    protected function shouldNotify(): bool
    {
        return !is_null($this->watcher) && $this->autoNotifyWatcher;
    }

    /**
     * Adds a rule to the current policy without notify.
     * 
     * @param string $sec
     * @param string $ptype
     * @param array $rule
     * 
     * @return bool
     */
    protected function addPolicyWithoutNotifyInternal(string $sec, string $ptype, array $rule): bool
    {
        if ($this->model->hasPolicy($sec, $ptype, $rule)) {
            return false;
        }

        if ($this->shouldPersist()) {
            try {
                $this->adapter->addPolicy($sec, $ptype, $rule);
            } catch (NotImplementedException $e) {
            }
        }

        $this->model->addPolicy($sec, $ptype, $rule);

        if ($sec == "g") {
            $this->buildIncrementalRoleLinks(Policy::POLICY_ADD, $ptype, [$rule]);
        }

        return true;
    }

    /**
     * Adds rules to the current policy without notify.
     * If autoRemoveRepeat == true, existing rules are automatically filtered
     * Otherwise, false is returned directly.
     * 
     * @param string $sec
     * @param string $ptype
     * @param array $rules
     * @param bool $autoRemoveRepeat
     * 
     * @return bool
     */
    protected function addPoliciesWithoutNotifyInternal(string $sec, string $ptype, array $rules, bool $autoRemoveRepeat): bool
    {
        if (!$autoRemoveRepeat) {
            if ($this->model->hasPolicies($sec, $ptype, $rules)) {
                return false;
            }
        }

        if ($this->shouldPersist() && $this->adapter instanceof BatchAdapter) {
            try {
                $this->adapter->addPolicies($sec, $ptype, $rules);
            } catch (NotImplementedException $e) {
            }
        }

        $this->model->addPolicies($sec, $ptype, $rules);

        if ($sec == "g") {
            $this->buildIncrementalRoleLinks(Policy::POLICY_ADD, $ptype, $rules);
        }

        return true;
    }

    /**
     * Updates a rule from the current policy without notify.
     * 
     * @param string $sec
     * @param string $ptype
     * @param array $oldRule
     * @param array $newRule
     * 
     * @return bool
     */
    protected function updatePolicyWithoutNotifyInternal(string $sec, string $ptype, array $oldRule, array $newRule): bool
    {
        if ($this->shouldPersist() && $this->adapter instanceof UpdatableAdapter) {
            try {
                $this->adapter->updatePolicy($sec, $ptype, $oldRule, $newRule);
            } catch (NotImplementedException $e) {
            }
        }

        $ruleUpdated = $this->model->updatePolicy($sec, $ptype, $oldRule, $newRule);
        if (!$ruleUpdated) {
            return false;
        }

        if ($sec == "g") {
            // remove the old rule
            $this->buildIncrementalRoleLinks(Policy::POLICY_REMOVE, $ptype, [$oldRule]);

            // add the new rule
            $this->buildIncrementalRoleLinks(Policy::POLICY_ADD, $ptype, [$newRule]);
        }

        return true;
    }

    /**
     * Updates rules from the current policy without notify.
     * 
     * @param string $sec
     * @param string $ptype
     * @param array $oldRules
     * @param array $newRules
     * 
     * @return bool
     */
    protected function updatePoliciesWithoutNotifyInternal(string $sec, string $ptype, array $oldRules, array $newRules): bool
    {
        if ($this->shouldPersist() && $this->adapter instanceof UpdatableAdapter) {
            try {
                $this->adapter->updatePolicies($sec, $ptype, $oldRules, $newRules);
            } catch (NotImplementedException $e) {
            }
        }

        $ruleUpdated = $this->model->updatePolicies($sec, $ptype, $oldRules, $newRules);
        if (!$ruleUpdated) {
            return false;
        }

        if ($sec == "g") {
            // remove the old rule
            $this->buildIncrementalRoleLinks(Policy::POLICY_REMOVE, $ptype, $oldRules);

            // add the new rule
            $this->buildIncrementalRoleLinks(Policy::POLICY_ADD, $ptype, $newRules);
        }

        return true;
    }

    /**
     * Removes a rule from the current policy without notify.
     * 
     * @param string $sec
     * @param string $ptype
     * @param array $rule
     * 
     * @return bool
     */
    protected function removePolicyWithoutNotifyInternal(string $sec, string $ptype, array $rule): bool
    {
        if ($this->shouldPersist()) {
            try {
                $this->adapter->removePolicy($sec, $ptype, $rule);
            } catch (NotImplementedException $e) {
            }
        }

        $ruleRemoved = $this->model->removePolicy($sec, $ptype, $rule);
        if (!$ruleRemoved) {
            return false;
        }

        if ($sec == "g") {
            $this->buildIncrementalRoleLinks(Policy::POLICY_REMOVE, $ptype, [$rule]);
        }

        return true;
    }

    /**
     * Removes rules from the current policy without notify.
     * 
     * @param string $sec
     * @param string $ptype
     * @param array $rules
     * 
     * @return bool
     */
    protected function removePoliciesWithoutNotifyInternal(string $sec, string $ptype, array $rules): bool
    {
        if (!$this->model->hasPolicies($sec, $ptype, $rules)) {
            return false;
        }

        if ($this->shouldPersist() && $this->adapter instanceof BatchAdapter) {
            try {
                $this->adapter->removePolicies($sec, $ptype, $rules);
            } catch (NotImplementedException $e) {
            }
        }

        $ruleRemoved = $this->model->removePolicies($sec, $ptype, $rules);
        if (!$ruleRemoved) {
            return false;
        }

        if ($sec == "g") {
            $this->buildIncrementalRoleLinks(Policy::POLICY_REMOVE, $ptype, $rules);
        }

        return true;
    }

    /**
     * Removes rules based on field filters from the current policy without notify.
     * 
     * @param string $sec
     * @param string $ptype
     * @param int $fieldIndex
     * @param string ...$fieldValues
     * 
     * @return bool
     */
    protected function removeFilteredPolicyWithoutNotifyInternal(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues): bool
    {
        if ($this->shouldPersist()) {
            try {
                $this->adapter->removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues);
            } catch (NotImplementedException $e) {
            }
        }

        $ruleRemoved = $this->model->removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues);
        if (!$ruleRemoved) {
            return false;
        }

        if ($sec == "g") {
            $this->buildIncrementalRoleLinks(Policy::POLICY_REMOVE, $ptype, $ruleRemoved);
        }

        return true;
    }

    /**
     * Updates rules based on field filters from the current policy without notify.
     * 
     * @param string $sec
     * @param string $ptype
     * @param array $newRules
     * @param int $fieldIndex
     * @param string ...$fieldValues
     * 
     * @return array
     */
    protected function updateFilteredPoliciesWithoutNotifyInternal(string $sec, string $ptype, array $newRules, int $fieldIndex, string ...$fieldValues): array
    {
        $oldRules = [];
        if ($this->shouldPersist()) {
            try {
                if ($this->adapter instanceof UpdatableAdapter) {
                    $oldRules = $this->adapter->updateFilteredPolicies($sec, $ptype, $newRules, $fieldIndex, ...$fieldValues);
                }
            } catch (NotImplementedException $e) {
            }
        }

        $ruleChanged = $this->model->removePolicies($sec, $ptype, $oldRules);
        $this->model->addPolicies($sec, $ptype, $newRules);

        $ruleChanged = $ruleChanged && count($newRules) !== 0;
        if (!$ruleChanged) {
            return [];
        }

        if ($sec == "g") {
            // remove the old rules
            $this->buildIncrementalRoleLinks(Policy::POLICY_REMOVE, $ptype, $oldRules);
            // add the new rules
            $this->buildIncrementalRoleLinks(Policy::POLICY_ADD, $ptype, $newRules);
        }

        return $oldRules;
    }

    /**
     * Adds a rule to the current policy.
     *
     * @param string $sec
     * @param string $ptype
     * @param array $rule
     *
     * @return bool
     */
    protected function addPolicyInternal(string $sec, string $ptype, array $rule): bool
    {
        if (!$this->addPolicyWithoutNotifyInternal($sec, $ptype, $rule)) {
            return false;
        }

        if ($this->shouldNotify()) {
            if ($this->watcher instanceof WatcherEx) {
                $this->watcher->updateForAddPolicy($sec, $ptype, ...$rule);
            } else {
                $this->watcher->update();
            }
        }

        return true;
    }

    /**
     * Adds rules to the current policy.
     *
     * @param string $sec
     * @param string $ptype
     * @param array $rules
     *
     * @return bool
     * @throws Exceptions\CasbinException
     */
    protected function addPoliciesInternal(string $sec, string $ptype, array $rules, bool $autoRemoveRepeat): bool
    {
        if (!$this->addPoliciesWithoutNotifyInternal($sec, $ptype, $rules, $autoRemoveRepeat)) {
            return false;
        }

        if ($this->shouldNotify()) {
            $this->watcher->update();
        }

        return true;
    }

    /**
     * Updates a rule from the current policy.
     * 
     * @param string $sec
     * @param string $ptype
     * @param string[] $oldRule
     * @param string[] $newRule
     *
     * @return bool
     */
    protected function updatePolicyInternal(string $sec, string $ptype, array $oldRule, array $newRule): bool
    {
        if (!$this->updatePolicyWithoutNotifyInternal($sec, $ptype, $oldRule, $newRule)) {
            return false;
        }

        if ($this->shouldNotify()) {
            try {
                if ($this->watcher instanceof WatcherUpdatable) {
                    $this->watcher->updateForUpdatePolicy($oldRule, $newRule);
                } else {
                    $this->watcher->update();
                }
            } catch (\Exception $e) {
                $this->logger->logError($e);

                return false;
            }
        }

        return true;
    }

    /**
     * Updates rules from the current policy.
     * 
     * @param string $sec
     * @param string $ptype
     * @param string[][] $oldRules
     * @param string[][] $newRules
     * 
     * @return bool
     */
    protected function updatePoliciesInternal(string $sec, string $ptype, array $oldRules, array $newRules): bool
    {
        if (!$this->updatePoliciesWithoutNotifyInternal($sec, $ptype, $oldRules, $newRules)) {
            return false;
        }

        if ($this->shouldNotify()) {
            try {
                if ($this->watcher instanceof WatcherUpdatable) {
                    $this->watcher->updateForUpdatePolicies($oldRules, $newRules);
                } else {
                    $this->watcher->update();
                }
            } catch (\Exception $e) {
                $this->logger->logError($e);
                return false;
            }
        }

        return true;
    }

    /**
     * Removes a rule from the current policy.
     *
     * @param string $sec
     * @param string $ptype
     * @param array $rule
     *
     * @return bool
     */
    protected function removePolicyInternal(string $sec, string $ptype, array $rule): bool
    {
        if (!$this->removePolicyWithoutNotifyInternal($sec, $ptype, $rule)) {
            return false;
        }

        if ($this->shouldNotify()) {
            if ($this->watcher instanceof WatcherEx) {
                $this->watcher->updateForRemovePolicy($sec, $ptype, ...$rule);
            } else {
                $this->watcher->update();
            }
        }

        return true;
    }

    /**
     * Removes a rules from the current policy.
     *
     * @param string $sec
     * @param string $ptype
     * @param array $rules
     *
     * @return bool
     */
    protected function removePoliciesInternal(string $sec, string $ptype, array $rules): bool
    {
        if (!$this->removePoliciesWithoutNotifyInternal($sec, $ptype, $rules)) {
            return false;
        }

        if ($this->shouldNotify()) {
            // error intentionally ignored
            $this->watcher->update();
        }

        return true;
    }

    /**
     * Removes rules based on field filters from the current policy.
     *
     * @param string $sec
     * @param string $ptype
     * @param int $fieldIndex
     * @param string ...$fieldValues
     *
     * @return bool
     */
    protected function removeFilteredPolicyInternal(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues): bool
    {
        if (!$this->removeFilteredPolicyWithoutNotifyInternal($sec, $ptype, $fieldIndex, ...$fieldValues)) {
            return false;
        }

        if ($this->shouldNotify()) {
            // error intentionally ignored
            if ($this->watcher instanceof WatcherEx) {
                $this->watcher->updateForRemoveFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues);
            } else {
                $this->watcher->update();
            }
        }

        return true;
    }

    /**
     * Removes rules based on field filters from the current policy.
     * 
     * @param string $sec
     * @param string $ptype
     * @param array $newRules
     * @param int $fieldIndex
     * @param string ...$fieldValues
     * 
     * @return bool
     */
    protected function updateFilteredPoliciesInternal(string $sec, string $ptype, array $newRules, int $fieldIndex, string ...$fieldValues): bool
    {
        $oldRules = $this->updateFilteredPoliciesWithoutNotifyInternal($sec, $ptype, $newRules, $fieldIndex, ...$fieldValues);
        if (count($oldRules) === 0) {
            return false;
        }

        if ($this->shouldNotify()) {
            // error intentionally ignored
            if ($this->watcher instanceof WatcherUpdatable) {
                $this->watcher->updateForUpdatePolicies($oldRules, $newRules);
            } else {
                $this->watcher->update();
            }
            return true;
        }

        return true;
    }
}
