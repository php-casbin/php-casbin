<?php

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
     * @return mixed
     */
    protected function addPolicyInternal($sec, $ptype, array $rule)
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
     * @return mixed
     */
    protected function removePolicyInternal($sec, $ptype, array $rule)
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
     * @param mixed  ...$fieldValues
     *
     * @return bool
     */
    protected function removeFilteredPolicyInternal($sec, $ptype, $fieldIndex, ...$fieldValues)
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
