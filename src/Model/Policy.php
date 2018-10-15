<?php
namespace Casbin\Model;

use Casbin\Util\Log;

/**
 * Policy
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
        Log::logPrint("Policy:");
        foreach (['p', 'g'] as $sec) {
            if (!isset($this->model[$sec])) {
                return;
            }
            foreach ($this->model[$sec] as $key => $ast) {
                Log::logPrint($key, ": ", $ast->value, ": ", $ast->policy);
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
                $this->model[$sec][$key]->policy = null;
            }
        }
    }

    public function getPolicy($sec, $ptype)
    {
        return $this->model[$sec][$ptype]->policy;
    }

    public function hasPolicy($sec, $ptype, $rule)
    {
        foreach ($this->model[$sec][$ptype]->policy as $r) {
            if (empty(array_diff($rule, $r))) {
                return true;
            }
        }
        return false;
    }

    public function addPolicy($sec, $ptype, $rule)
    {
        if (!$this->hasPolicy($sec, $ptype, $rule)) {
            $this->model[$sec][$ptype]->policy[] = $rule;
            return true;
        }
        return false;
    }

    public function removePolicy($sec, $ptype, $rule)
    {
        foreach ($this->model[$sec][$ptype]->policy as $i => $r) {
            if (empty(array_diff($rule, $r))) {
                unset($this->model[$sec][$ptype]->policy[$i]);
                return true;
            }
        }
        return false;
    }

    public function removeFilteredPolicy($sec, $ptype, $fieldIndex, ...$fieldValues)
    {

    }

    public function GetValuesForFieldInPolicy($sec, $ptype, $fieldIndex)
    {

    }
}
