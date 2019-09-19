<?php

declare(strict_types=1);

namespace Casbin;

use Casbin\Exceptions\NotImplementedException;

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
        $ruleAdded = $this->model->addPolicy($sec, $ptype, $rule);
        if (!$ruleAdded) {
            return $ruleAdded;
        }

        if (!is_null($this->adapter) && $this->autoSave) {
            try {
                $this->adapter->addPolicy($sec, $ptype, $rule);
            } catch (NotImplementedException $e) {
            }

            if (!is_null($this->watcher)) {
                // error intentionally ignored
                $this->watcher->update();
            }
        }

        return $ruleAdded;
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

        if (!is_null($this->adapter) && $this->autoSave) {
            try {
                $this->adapter->removePolicy($sec, $ptype, $rule);
            } catch (NotImplementedException $e) {
            }

            if (!is_null($this->watcher)) {
                // error intentionally ignored
                $this->watcher->update();
            }
        }

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

        if (!is_null($this->adapter) && $this->autoSave) {
            try {
                $this->adapter->removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues);
            } catch (NotImplementedException $e) {
            }

            if (!is_null($this->watcher)) {
                // error intentionally ignored
                $this->watcher->update();
            }
        }

        return $ruleRemoved;
    }
}
