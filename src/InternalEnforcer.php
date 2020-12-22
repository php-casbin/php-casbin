<?php

declare(strict_types=1);

namespace Casbin;

use Casbin\Exceptions\NotImplementedException;
use Casbin\Persist\BatchAdapter;
use Casbin\Persist\UpdatableAdapter;

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


        $this->updateWatcher();

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
    protected function addPoliciesInternal(string $sec, string $ptype, array $rules): bool
    {
        if ($this->model->hasPolicies($sec, $ptype, $rules)) {
            return false;
        }

        if ($this->shouldPersist() && $this->adapter instanceof BatchAdapter) {
            try {
                $this->adapter->addPolicies($sec, $ptype, $rules);
            } catch (NotImplementedException $e) {
            }
        }

        $this->model->addPolicies($sec, $ptype, $rules);

        $this->updateWatcher();

        return true;
    }

    /**
     * @param string $sec
     * @param string $ptype
     * @param string[] $oldRule
     * @param string[] $newRule
     *
     * @return bool
     */
    protected function updatePolicyInternal(string $sec, string $ptype, array $oldRule, array $newRule): bool
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

        $this->updateWatcher();

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


        $this->updateWatcher();

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

        $this->updateWatcher();

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


        $this->updateWatcher();

        return true;
    }

    /**
     * Check $this->watcher ans $this->autoNotifyWatcher.
     */
    private function updateWatcher(): void
    {
        if (!is_null($this->watcher) && $this->autoNotifyWatcher) {
            $this->watcher->update();
        }
    }
}
