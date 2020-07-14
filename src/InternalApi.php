<?php

declare(strict_types=1);

namespace Casbin;

use Casbin\Exceptions\NotImplementedException;
use Casbin\Persist\BatchAdapter;

/**
 * Trait InternalApi.
 *
 * @author techlee@qq.com
 */
trait InternalApi
{
    /**
     * adds a rule to the current policy.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     *
     * @return bool
     */
    protected function addPolicyInternal(string $sec, string $ptype, array $rule): bool
    {
        if ($this->model->hasPolicy($sec, $ptype, $rule)) {
            return false;
        }

        $this->model->addPolicy($sec, $ptype, $rule);

        if ($this->ShouldPersist()) {
            try {
                $this->adapter->addPolicy($sec, $ptype, $rule);
            } catch (NotImplementedException $e) {
            }
        }
        $this->checkWatcher();

        return true;
    }

    /**
     * adds a rules to the current policy.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rules
     *
     * @return bool
     */
    protected function addPoliciesInternal(string $sec, string $ptype, array $rules): bool
    {
        if ($this->model->hasPolicies($sec, $ptype, $rules)) {
            return false;
        }

        $this->model->addPolicies($sec, $ptype, $rules);

        if ($this->ShouldPersist() && $this->adapter instanceof BatchAdapter) {
            try {
                $this->adapter->addPolicies($sec, $ptype, $rules);
            } catch (NotImplementedException $e) {
            }
        }
        $this->checkWatcher();

        return true;
    }

    /**
     * removes a rule from the current policy.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     *
     * @return bool
     */
    protected function removePolicyInternal(string $sec, string $ptype, array $rule): bool
    {
        $ruleRemoved = $this->model->removePolicy($sec, $ptype, $rule);
        if (!$ruleRemoved) {
            return $ruleRemoved;
        }

        if ($this->ShouldPersist()) {
            try {
                $this->adapter->removePolicy($sec, $ptype, $rule);
            } catch (NotImplementedException $e) {
            }
        }
        $this->checkWatcher();

        return $ruleRemoved;
    }

    /**
     * removes a rules from the current policy.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rules
     *
     * @return bool
     */
    protected function removePoliciesInternal(string $sec, string $ptype, array $rules): bool
    {
        $ruleRemoved = $this->model->removePolicies($sec, $ptype, $rules);
        if (!$ruleRemoved) {
            return $ruleRemoved;
        }

        if ($this->ShouldPersist() && $this->adapter instanceof BatchAdapter) {
            try {
                $this->adapter->removePolicies($sec, $ptype, $rules);
            } catch (NotImplementedException $e) {
            }
        }
        $this->checkWatcher();

        return $ruleRemoved;
    }

    /**
     * removes rules based on field filters from the current policy.
     *
     * @param string $sec
     * @param string $ptype
     * @param int    $fieldIndex
     * @param string ...$fieldValues
     *
     * @return bool
     */
    protected function removeFilteredPolicyInternal(string $sec, string $ptype, int $fieldIndex, string ...$fieldValues): bool
    {
        $ruleRemoved = $this->model->removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues);
        if (!$ruleRemoved) {
            return $ruleRemoved;
        }

        if ($this->ShouldPersist()) {
            try {
                $this->adapter->removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues);
            } catch (NotImplementedException $e) {
            }
        }
        $this->checkWatcher();

        return $ruleRemoved;
    }

    /**
     * check $this->watcher ans $this->autoNotifyWatcher.
     */
    private function checkWatcher(): void
    {
        if (!is_null($this->watcher) && $this->autoNotifyWatcher) {
            // error intentionally ignored
            $this->watcher->update();
        }
    }

    private function ShouldPersist(): bool
    {
        return !is_null($this->adapter) && $this->autoNotifyWatcher;
    }
}
