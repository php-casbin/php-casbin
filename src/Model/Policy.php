<?php

namespace Casbin\Model;

use Casbin\Log\Log;
use Casbin\Util\Util;

/**
 * Policy.
 *
 * @author techlee@qq.com
 */
trait Policy
{
    public function buildRoleLinks($rm)
    {
        if (!isset($this->model['g'])) {
            return;
        }
        foreach ($this->model['g'] as $ast) {
            $ast->buildRoleLinks($rm);
        }
    }

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

    public function getPolicy($sec, $ptype)
    {
        return $this->model[$sec][$ptype]->policy;
    }

    // GetFilteredPolicy gets rules based on field filters from a policy.
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

    public function hasPolicy($sec, $ptype, $rule)
    {
        if (!isset($this->model[$sec][$ptype])) {
            return false;
        }

        foreach ($this->model[$sec][$ptype]->policy as $r) {
            if (empty(array_diff($rule, $r))) {
                return true;
            }
        }

        return false;
    }

    public function addPolicy($sec, $ptype, array $rule)
    {
        if (!$this->hasPolicy($sec, $ptype, $rule)) {
            $this->model[$sec][$ptype]->policy[] = $rule;

            return true;
        }

        return false;
    }

    public function removePolicy($sec, $ptype, array $rule)
    {
        foreach ($this->model[$sec][$ptype]->policy as $i => $r) {
            if (empty(array_diff($rule, $r))) {
                array_splice($this->model[$sec][$ptype]->policy, $i, 1);

                return true;
            }
        }

        return false;
    }

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
