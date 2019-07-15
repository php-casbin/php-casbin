<?php

namespace Casbin\Model;

use Casbin\Log\Log;
use Casbin\Rbac\RoleManager;
use Casbin\Util\Util;

/**
 * Trait Policy.
 *
 * @author techlee@qq.com
 */
trait Policy
{
    /**
     * initializes the roles in RBAC.
     *
     * @param RoleManager $rm
     */
    public function buildRoleLinks($rm)
    {
        if (!isset($this->model['g'])) {
            return;
        }
        foreach ($this->model['g'] as $ast) {
            $ast->buildRoleLinks($rm);
        }
    }

    /**
     * prints the policy to log.
     */
    public function printPolicy()
    {
        Log::logPrint('Policy:');
        foreach (['p', 'g'] as $sec) {
            if (!isset($this->model[$sec])) {
                return;
            }
            foreach ($this->model[$sec] as $key => $ast) {
                Log::logPrint($key, ': ', $ast->value, ': ', $ast->policy);
            }
        }
    }

    /**
     * clears all current policy.
     */
    public function clearPolicy()
    {
        foreach (['p', 'g'] as $sec) {
            if (!isset($this->model[$sec])) {
                return;
            }
            foreach ($this->model[$sec] as $key => $ast) {
                $this->model[$sec][$key]->policy = [];
            }
        }
    }

    /**
     * gets all rules in a policy.
     *
     * @param string $sec
     * @param string $ptype
     *
     * @return array
     */
    public function getPolicy($sec, $ptype)
    {
        return $this->model[$sec][$ptype]->policy;
    }

    /**
     * gets rules based on field filters from a policy.
     *
     * @param string $sec
     * @param string $ptype
     * @param int    $fieldIndex
     * @param mixed  ...$fieldValues
     *
     * @return array
     */
    public function getFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues)
    {
        $res = [];

        foreach ($this->model[$sec][$ptype]->policy as $rule) {
            $matched = true;
            foreach ($fieldValues as $i => $fieldValue) {
                if ('' != $fieldValue && $rule[$fieldIndex + $i] != $fieldValue) {
                    $matched = false;

                    break;
                }
            }

            if ($matched) {
                $res[] = $rule;
            }
        }

        return $res;
    }

    /**
     * determines whether a model has the specified policy rule.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     *
     * @return bool
     */
    public function hasPolicy($sec, $ptype, $rule)
    {
        if (!isset($this->model[$sec][$ptype])) {
            return false;
        }

        return in_array($rule, $this->model[$sec][$ptype]->policy, true);
    }

    /**
     * adds a policy rule to the model.
     *
     * @param $sec
     * @param $ptype
     * @param array $rule
     *
     * @return bool
     */
    public function addPolicy($sec, $ptype, array $rule)
    {
        if (!$this->hasPolicy($sec, $ptype, $rule)) {
            $this->model[$sec][$ptype]->policy[] = $rule;

            return true;
        }

        return false;
    }

    /**
     * removes a policy rule from the model.
     *
     * @param string $sec
     * @param string $ptype
     * @param array  $rule
     *
     * @return bool
     */
    public function removePolicy($sec, $ptype, array $rule)
    {
        if (!isset($this->model[$sec][$ptype])) {
            return false;
        }

        $offset = array_search($rule, $this->model[$sec][$ptype]->policy, true);

        if (false === $offset) {
            return false;
        }

        array_splice($this->model[$sec][$ptype]->policy, $offset, 1);

        return true;
    }

    /**
     * removes policy rules based on field filters from the model.
     *
     * @param string $sec
     * @param string $ptype
     * @param int    $fieldIndex
     * @param mixed  ...$fieldValues
     *
     * @return bool
     */
    public function removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues)
    {
        $tmp = [];
        $res = false;

        if (!isset($this->model[$sec][$ptype])) {
            return $res;
        }

        foreach ($this->model[$sec][$ptype]->policy as $rule) {
            $matched = true;
            foreach ($fieldValues as $i => $fieldValue) {
                if ('' != $fieldValue && $rule[$fieldIndex + $i] != $fieldValue) {
                    $matched = false;

                    break;
                }
            }

            if ($matched) {
                $res = true;
            } else {
                $tmp[] = $rule;
            }
        }

        $this->model[$sec][$ptype]->policy = $tmp;

        return $res;
    }

    /**
     * gets all values for a field for all rules in a policy, duplicated values are removed.
     *
     * @param string $sec
     * @param string $ptype
     * @param int    $fieldIndex
     *
     * @return array
     */
    public function getValuesForFieldInPolicy($sec, $ptype, $fieldIndex)
    {
        $values = [];

        if (!isset($this->model[$sec][$ptype])) {
            return $values;
        }

        foreach ($this->model[$sec][$ptype]->policy as $rule) {
            $values[] = $rule[$fieldIndex];
        }

        Util::arrayRemoveDuplicates($values);

        return $values;
    }
}
